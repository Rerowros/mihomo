package statistic

import (
	"sort"
	"sync"
	"sync/atomic"
)

// InboundStat is the traffic of one inbound listener. Unlike Xray, mihomo
// keeps it separately from the per-user counters, so resetting an inbound
// counter does not erase the users' traffic.
type InboundStat struct {
	Inbound  string `json:"inbound"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

type inboundCounters struct {
	upload   atomic.Int64
	download atomic.Int64
	// drained* keep what the resets took, see userCounters.
	drainedUp   atomic.Int64
	drainedDown atomic.Int64
}

// InboundManager keeps the traffic counters of the inbound listeners, including
// traffic of connections that have no authenticated user.
type InboundManager struct {
	mu       sync.RWMutex
	inbounds map[string]*inboundCounters
	resetMu  sync.Mutex // see UserManager.resetMu
}

// DefaultInboundManager is filled by the inbound trackers.
var DefaultInboundManager = &InboundManager{inbounds: make(map[string]*inboundCounters)}

func (m *InboundManager) counters(inbound string) *inboundCounters {
	m.mu.RLock()
	counters := m.inbounds[inbound]
	m.mu.RUnlock()
	if counters != nil {
		return counters
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if counters = m.inbounds[inbound]; counters == nil {
		counters = &inboundCounters{}
		m.inbounds[inbound] = counters
	}
	return counters
}

func (m *InboundManager) PushUploaded(inbound string, size int64) {
	if inbound != "" {
		m.counters(inbound).upload.Add(size)
	}
}

func (m *InboundManager) PushDownloaded(inbound string, size int64) {
	if inbound != "" {
		m.counters(inbound).download.Add(size)
	}
}

// ResetTraffic returns the counters and zeroes only the requested directions.
func (m *InboundManager) ResetTraffic(inbound string, resetUpload, resetDownload bool) (upload, download int64, found bool) {
	if inbound == "" {
		return 0, 0, false
	}
	m.mu.RLock()
	counters := m.inbounds[inbound]
	m.mu.RUnlock()
	if counters == nil {
		return 0, 0, false
	}
	m.resetMu.Lock()
	defer m.resetMu.Unlock()
	if resetUpload {
		upload = counters.upload.Swap(0)
		counters.drainedUp.Add(upload)
	} else {
		upload = counters.upload.Load()
	}
	if resetDownload {
		download = counters.download.Swap(0)
		counters.drainedDown.Add(download)
	} else {
		download = counters.download.Load()
	}
	return upload, download, true
}

// Snapshot returns the traffic of every inbound that has been used.
func (m *InboundManager) Snapshot() []InboundStat {
	m.mu.RLock()
	stats := make([]InboundStat, 0, len(m.inbounds))
	for inbound, counters := range m.inbounds {
		stats = append(stats, InboundStat{
			Inbound:  inbound,
			Upload:   counters.upload.Load(),
			Download: counters.download.Load(),
		})
	}
	m.mu.RUnlock()
	sort.Slice(stats, func(i, j int) bool { return stats[i].Inbound < stats[j].Inbound })
	return stats
}

// Totals returns the cumulative traffic of every inbound since the start of
// the process; the resets of the Xray API do not lower it.
func (m *InboundManager) Totals() []InboundStat {
	m.resetMu.Lock()
	defer m.resetMu.Unlock()
	m.mu.RLock()
	stats := make([]InboundStat, 0, len(m.inbounds))
	for inbound, counters := range m.inbounds {
		stats = append(stats, InboundStat{
			Inbound:  inbound,
			Upload:   counters.drainedUp.Load() + counters.upload.Load(),
			Download: counters.drainedDown.Load() + counters.download.Load(),
		})
	}
	m.mu.RUnlock()
	sort.Slice(stats, func(i, j int) bool { return stats[i].Inbound < stats[j].Inbound })
	return stats
}
