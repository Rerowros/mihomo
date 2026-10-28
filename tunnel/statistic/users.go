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
}

// UserManager keeps the per-user traffic counters of the inbounds. The
// counters are payload bytes on the outbound side, the same bytes the global
// manager counts; they live in memory and are dropped on restart, like Xray's
// StatsService.
type UserManager struct {
	mu    sync.RWMutex
	users map[UserKey]*userCounters
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
	for _, c := range counters {
		if resetUpload {
			upload += c.upload.Swap(0)
		} else {
			upload += c.upload.Load()
		}
		if resetDownload {
			download += c.download.Swap(0)
		} else {
			download += c.download.Load()
		}
	}
	return upload, download, true
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
			upload = counters.upload.Swap(0)
			download = counters.download.Swap(0)
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
