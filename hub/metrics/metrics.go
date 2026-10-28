// Package metrics renders the Prometheus metrics of the core (GET /metrics)
// and answers the health probes (GET /healthz, GET /readyz).
//
// Nothing here runs unless the controller is asked: the metrics are read from
// the counters the core keeps anyway (the global traffic, the per-inbound and
// per-user counters, the limits), so a client build that never scrapes pays
// nothing on the connection path.
package metrics

import (
	"bufio"
	"io"
	"math"
	"runtime"
	"runtime/debug"
	rtmetrics "runtime/metrics"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// Options are the `metrics` section and `health-without-auth`.
type Options struct {
	Enable            bool
	PerUser           bool
	HealthWithoutAuth bool
}

var (
	options   atomic.Pointer[Options]
	startTime = time.Now()
)

// SetOptions applies the options (on every configuration load).
func SetOptions(o Options) {
	options.Store(&o)
}

// Current returns the options in force; all off before the first load.
func Current() Options {
	if o := options.Load(); o != nil {
		return *o
	}
	return Options{}
}

// Live reports whether the tunnel is running: false while the configuration
// is being (re)loaded, with the state as the reason.
func Live() (bool, string) {
	if s := tunnel.Status(); s != tunnel.Running {
		return false, s.String()
	}
	return true, ""
}

// Ready reports whether the configuration is applied and every listener of
// the `listeners` section listens.
func Ready() (bool, string) {
	if ok, reason := Live(); !ok {
		return false, "tunnel " + reason
	}
	if n := listener.FailedInboundListeners(); n > 0 {
		return false, "listeners failed to start"
	}
	return true, ""
}

// Write renders all the metrics in the text exposition format.
func Write(out io.Writer, o Options) error {
	bw := bufio.NewWriterSize(out, 32*1024)
	w := newWriter(bw)
	writeProcess(w)
	writeTraffic(w)
	writeInbounds(w)
	writeUsers(w, o.PerUser)
	writeLimits(w)
	writeEvents(w)
	return bw.Flush()
}

// runtime/metrics samples.
var (
	sampleOnce  sync.Once
	sampleNames []string
)

const (
	rmGoroutines = "/sched/goroutines:goroutines"
	rmHeap       = "/memory/classes/heap/objects:bytes"
	rmGCCycles   = "/gc/cycles/total:gc-cycles"
)

func runtimeSamples() []rtmetrics.Sample {
	sampleOnce.Do(func() {
		have := map[string]bool{}
		for _, d := range rtmetrics.All() {
			have[d.Name] = true
		}
		for _, name := range []string{rmGoroutines, rmHeap, rmGCCycles} {
			if have[name] {
				sampleNames = append(sampleNames, name)
			}
		}
	})
	samples := make([]rtmetrics.Sample, len(sampleNames))
	for i, name := range sampleNames {
		samples[i].Name = name
	}
	rtmetrics.Read(samples)
	return samples
}

// MemoryLimit returns the soft memory limit the Go runtime enforces, set by
// GOMEMLIMIT or debug.SetMemoryLimit, and 0 when there is none: the runtime
// spells "unlimited" as math.MaxInt64.
func MemoryLimit() uint64 {
	// a negative argument only reads the limit
	limit := debug.SetMemoryLimit(-1)
	if limit == math.MaxInt64 || limit < 0 {
		return 0
	}
	return uint64(limit)
}

func writeProcess(w writer) {
	w.family("mihomo_build_info", "gauge", "Build information of the core.")
	w.int("mihomo_build_info", 1, "version", C.Version, "go_version", runtime.Version())

	w.family("mihomo_start_time_seconds", "gauge", "Start time of the process since the unix epoch in seconds.")
	w.float("mihomo_start_time_seconds", float64(startTime.UnixNano())/1e9)
	w.family("mihomo_uptime_seconds", "gauge", "Seconds since the process started.")
	w.float("mihomo_uptime_seconds", time.Since(startTime).Seconds())

	for _, s := range runtimeSamples() {
		if s.Value.Kind() != rtmetrics.KindUint64 {
			continue
		}
		switch s.Name {
		case rmGoroutines:
			w.family("mihomo_goroutines", "gauge", "Number of goroutines.")
			w.int("mihomo_goroutines", int64(s.Value.Uint64()))
		case rmHeap:
			w.family("mihomo_heap_bytes", "gauge", "Bytes of live and not yet swept heap objects.")
			w.int("mihomo_heap_bytes", int64(s.Value.Uint64()))
		case rmGCCycles:
			w.family("mihomo_gc_cycles_total", "counter", "Completed GC cycles.")
			w.int("mihomo_gc_cycles_total", int64(s.Value.Uint64()))
		}
	}

	w.family("mihomo_resident_memory_bytes", "gauge", "Resident memory of the process in bytes.")
	w.int("mihomo_resident_memory_bytes", int64(statistic.DefaultManager.Memory()))
	w.family("mihomo_memory_limit_bytes", "gauge", "Soft memory limit of the Go runtime (GOMEMLIMIT), 0 when unlimited.")
	w.int("mihomo_memory_limit_bytes", int64(MemoryLimit()))

	if open, max, ok := openFDs(); ok {
		w.family("mihomo_open_fds", "gauge", "Number of open file descriptors.")
		w.int("mihomo_open_fds", open)
		if max > 0 {
			w.family("mihomo_max_fds", "gauge", "Limit of open file descriptors.")
			w.int("mihomo_max_fds", max)
		}
	}

	live, _ := Live()
	ready, _ := Ready()
	w.family("mihomo_live", "gauge", "1 when the tunnel is running (GET /healthz).")
	w.int("mihomo_live", boolValue(live))
	w.family("mihomo_ready", "gauge", "1 when the configuration is applied and every listener listens (GET /readyz).")
	w.int("mihomo_ready", boolValue(ready))
	w.family("mihomo_listeners_failed", "gauge", "Listeners of the configuration that failed to start.")
	w.int("mihomo_listeners_failed", int64(listener.FailedInboundListeners()))
}

// writeTraffic reports the global counters of /traffic and /connections. They
// restart from zero only on a statistic reset, which Prometheus treats as a
// counter reset.
func writeTraffic(w writer) {
	up, down := statistic.DefaultManager.Total()
	w.family("mihomo_upload_bytes_total", "counter", "Bytes sent to the outbounds since start (or the last statistic reset).")
	w.int("mihomo_upload_bytes_total", up)
	w.family("mihomo_download_bytes_total", "counter", "Bytes received from the outbounds since start (or the last statistic reset).")
	w.int("mihomo_download_bytes_total", down)
}

// writeInbounds reports the open connections and the cumulative traffic of
// every inbound; the connections are counted in one pass over the trackers.
func writeInbounds(w writer) {
	var total int64
	byInbound := map[string]int64{}
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		total++
		if m := c.Info().Metadata; m != nil && m.InName != "" {
			byInbound[m.InName]++
		}
		return true
	})
	w.family("mihomo_connections", "gauge", "Open tracked connections.")
	w.int("mihomo_connections", total)

	totals := statistic.DefaultInboundManager.Totals()
	for _, t := range totals {
		if _, ok := byInbound[t.Inbound]; !ok {
			byInbound[t.Inbound] = 0 // an inbound with traffic and no open connection
		}
	}
	w.family("mihomo_inbound_connections", "gauge", "Open tracked connections by inbound.")
	for _, name := range sortedKeys(byInbound) {
		w.int("mihomo_inbound_connections", byInbound[name], "inbound", name)
	}
	w.family("mihomo_inbound_upload_bytes_total", "counter", "Bytes sent by the clients of an inbound since start; Xray API resets do not lower it.")
	for _, t := range totals {
		w.int("mihomo_inbound_upload_bytes_total", t.Upload, "inbound", t.Inbound)
	}
	w.family("mihomo_inbound_download_bytes_total", "counter", "Bytes received by the clients of an inbound since start; Xray API resets do not lower it.")
	for _, t := range totals {
		w.int("mihomo_inbound_download_bytes_total", t.Download, "inbound", t.Inbound)
	}
}

// writeUsers reports the number of online users by inbound and, with
// metrics.per-user, the series of every user (one series per user and
// family: high cardinality, so it is opt-in).
func writeUsers(w writer, perUser bool) {
	totals := statistic.DefaultUserManager.Totals()
	online := map[string]int64{}
	known := map[string]int64{}
	for _, t := range totals {
		known[t.Inbound]++
		if t.Conns > 0 {
			online[t.Inbound]++
		}
	}
	w.family("mihomo_inbound_users_online", "gauge", "Users of an inbound with at least one open connection.")
	for _, name := range sortedKeys(known) {
		w.int("mihomo_inbound_users_online", online[name], "inbound", name)
	}
	if !perUser {
		return
	}
	w.family("mihomo_user_upload_bytes_total", "counter", "Bytes sent by a user since start; panel resets do not lower it.")
	for _, t := range totals {
		w.int("mihomo_user_upload_bytes_total", t.Upload, "inbound", t.Inbound, "user", t.User)
	}
	w.family("mihomo_user_download_bytes_total", "counter", "Bytes received by a user since start; panel resets do not lower it.")
	for _, t := range totals {
		w.int("mihomo_user_download_bytes_total", t.Download, "inbound", t.Inbound, "user", t.User)
	}
	w.family("mihomo_user_connections", "gauge", "Open connections of a user.")
	for _, t := range totals {
		w.int("mihomo_user_connections", t.Conns, "inbound", t.Inbound, "user", t.User)
	}
}

// writeLimits reports the connections refused by the user limits.
func writeLimits(w writer) {
	w.family("mihomo_user_limit_rejections_total", "counter", "Connections refused by the user limits, by reason.")
	for i, n := range statistic.DefaultLimitManager.Rejections() {
		w.int("mihomo_user_limit_rejections_total", int64(n), "reason", statistic.RejectReasons[i])
	}
}

// writeEvents reports the event stream (GET /events).
func writeEvents(w writer) {
	b := eventbus.Default
	w.family("mihomo_event_subscribers", "gauge", "Open GET /events streams.")
	w.int("mihomo_event_subscribers", int64(b.Subscribers()))
	w.family("mihomo_events_published_total", "counter", "Events delivered to at least one GET /events stream, by type.")
	for i, n := range b.Published() {
		w.int("mihomo_events_published_total", int64(n), "type", eventbus.Types[i])
	}
	w.family("mihomo_events_dropped_total", "counter", "Events dropped for GET /events streams that read too slowly.")
	w.int("mihomo_events_dropped_total", int64(b.Dropped()))
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
