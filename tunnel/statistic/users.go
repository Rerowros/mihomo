package statistic

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// UserKeyOf returns the authenticated user of a connection, if it came from a
// user-aware inbound. Internal hops (DNS, dialer-proxy) have no InUser.
func UserKeyOf(metadata *C.Metadata) (UserKey, bool) {
	if metadata == nil || metadata.InUser == "" {
		return UserKey{}, false
	}
	return UserKey{Inbound: metadata.InName, User: metadata.InUser}, true
}

// UserKey identifies one user of one inbound. mihomo has no global user name
// like Xray's email: the same person may use different names on different
// inbounds, so the inbound is part of the key.
type UserKey struct {
	Inbound string
	User    string
}

type userCounters struct {
	upload     atomic.Int64
	download   atomic.Int64
	conns      atomic.Int64
	lastActive atomic.Int64 // unix seconds

	// drainedUp and drainedDown keep what the resets took from upload and
	// download, so the cumulative totals (Totals, /metrics) never go down.
	// They change only under UserManager.resetMu, off the hot path.
	drainedUp   atomic.Int64
	drainedDown atomic.Int64
}

// UserManager keeps the per-user traffic counters of the inbounds. The
// counters are payload bytes on the outbound side, the same bytes the global
// manager counts; they live in memory and are dropped on restart, like Xray's
// StatsService.
type UserManager struct {
	mu    sync.RWMutex
	users map[UserKey]*userCounters
	// resetMu orders the resets against Totals, so a reset is never seen
	// half done (taken from the counter but not yet added to the drained).
	resetMu sync.Mutex
}

// DefaultUserManager is filled by the inbound trackers.
var DefaultUserManager = &UserManager{users: make(map[UserKey]*userCounters)}

func (m *UserManager) counters(key UserKey) *userCounters {
	m.mu.RLock()
	counters := m.users[key]
	m.mu.RUnlock()
	if counters != nil {
		return counters
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if counters = m.users[key]; counters == nil {
		counters = &userCounters{}
		m.users[key] = counters
	}
	return counters
}

// Open records a new connection of the user.
func (m *UserManager) Open(key UserKey) {
	counters := m.counters(key)
	counters.conns.Add(1)
	counters.lastActive.Store(time.Now().Unix())
}

// Close records the end of one connection.
func (m *UserManager) Close(key UserKey) {
	m.counters(key).conns.Add(-1)
}

// PushUploaded adds uploaded payload bytes to the user.
func (m *UserManager) PushUploaded(key UserKey, size int64) {
	counters := m.counters(key)
	counters.upload.Add(size)
	counters.lastActive.Store(time.Now().Unix())
}

// PushDownloaded adds downloaded payload bytes to the user.
func (m *UserManager) PushDownloaded(key UserKey, size int64) {
	counters := m.counters(key)
	counters.download.Add(size)
	counters.lastActive.Store(time.Now().Unix())
}

// UserStat is the JSON form returned by the controller.
type UserStat struct {
	Inbound    string `json:"inbound"`
	User       string `json:"user"`
	Upload     int64  `json:"upload"`
	Download   int64  `json:"download"`
	Conns      int64  `json:"conns"`
	LastActive int64  `json:"lastActive"`
}

// ResetTraffic returns the counters and zeroes the requested directions in
// one atomic step per counter, so a panel that reads uplink with reset does not
// lose downlink.
func (m *UserManager) ResetTraffic(inbound, user string, resetUpload, resetDownload bool) (upload, download int64, found bool) {
	m.mu.RLock()
	keys := make([]UserKey, 0, len(m.users))
	for key := range m.users {
		if inbound != "" && key.Inbound != inbound {
			continue
		}
		if user != "" && key.User != user {
			continue
		}
		keys = append(keys, key)
	}
	counters := make([]*userCounters, 0, len(keys))
	for _, key := range keys {
		if c := m.users[key]; c != nil {
			counters = append(counters, c)
		}
	}
	m.mu.RUnlock()

	if len(counters) == 0 {
		return 0, 0, false
	}
	m.resetMu.Lock()
	defer m.resetMu.Unlock()
	for _, c := range counters {
		if resetUpload {
			upload += c.drainUp()
		} else {
			upload += c.upload.Load()
		}
		if resetDownload {
			download += c.drainDown()
		} else {
			download += c.download.Load()
		}
	}
	return upload, download, true
}

// drainUp and drainDown zero a counter and keep what it held in the
// cumulative total; the caller holds UserManager.resetMu.
func (c *userCounters) drainUp() int64 {
	v := c.upload.Swap(0)
	c.drainedUp.Add(v)
	return v
}

func (c *userCounters) drainDown() int64 {
	v := c.download.Swap(0)
	c.drainedDown.Add(v)
	return v
}

// UserTotal is the cumulative traffic of one user since the start of the
// process: the resets of the panel API (Snapshot, ResetTraffic, Xray
// QueryStats with reset) do not lower it, so it is a Prometheus counter.
type UserTotal struct {
	Inbound  string
	User     string
	Upload   int64
	Download int64
	Conns    int64
}

// Totals returns the cumulative traffic and the open connections of every
// user, sorted by inbound and user.
func (m *UserManager) Totals() []UserTotal {
	m.resetMu.Lock()
	defer m.resetMu.Unlock()
	m.mu.RLock()
	totals := make([]UserTotal, 0, len(m.users))
	for key, c := range m.users {
		totals = append(totals, UserTotal{
			Inbound:  key.Inbound,
			User:     key.User,
			Upload:   c.drainedUp.Load() + c.upload.Load(),
			Download: c.drainedDown.Load() + c.download.Load(),
			Conns:    c.conns.Load(),
		})
	}
	m.mu.RUnlock()
	sort.Slice(totals, func(i, j int) bool {
		if totals[i].Inbound != totals[j].Inbound {
			return totals[i].Inbound < totals[j].Inbound
		}
		return totals[i].User < totals[j].User
	})
	return totals
}

// Snapshot returns the counters, optionally filtered by inbound and user. With
// reset, the traffic counters restart from zero, atomically with the read, so
// a panel that polls and resets once a period neither loses nor counts a byte
// twice (the analogue of Xray's QueryStats reset).
func (m *UserManager) Snapshot(inbound, user string, reset bool) []UserStat {
	m.mu.RLock()
	keys := make([]UserKey, 0, len(m.users))
	for key := range m.users {
		if inbound != "" && key.Inbound != inbound {
			continue
		}
		if user != "" && key.User != user {
			continue
		}
		keys = append(keys, key)
	}
	m.mu.RUnlock()

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Inbound != keys[j].Inbound {
			return keys[i].Inbound < keys[j].Inbound
		}
		return keys[i].User < keys[j].User
	})

	if reset {
		m.resetMu.Lock()
		defer m.resetMu.Unlock()
	}
	stats := make([]UserStat, 0, len(keys))
	for _, key := range keys {
		m.mu.RLock()
		counters := m.users[key]
		m.mu.RUnlock()
		if counters == nil {
			continue
		}
		upload := counters.upload.Load()
		download := counters.download.Load()
		if reset {
			upload = counters.drainUp()
			download = counters.drainDown()
		}
		stats = append(stats, UserStat{
			Inbound:    key.Inbound,
			User:       key.User,
			Upload:     upload,
			Download:   download,
			Conns:      counters.conns.Load(),
			LastActive: counters.lastActive.Load(),
		})
	}
	return stats
}
