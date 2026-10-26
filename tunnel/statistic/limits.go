package statistic

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrUserLimitExpired  = errors.New("user expired")
	ErrUserQuotaExceeded = errors.New("user quota exceeded")
	ErrUserMaxConns      = errors.New("user connection limit reached")
)

// UserLimit is the policy of one inbound user. Zero means "no limit".
type UserLimit struct {
	Inbound  string `json:"inbound" yaml:"inbound"`
	User     string `json:"user" yaml:"user"`
	MaxConns int    `json:"maxConns,omitempty" yaml:"max-conns,omitempty"`
	UpBps    int64  `json:"upBps,omitempty" yaml:"up-bps,omitempty"`
	DownBps  int64  `json:"downBps,omitempty" yaml:"down-bps,omitempty"`
	Quota    int64  `json:"quota,omitempty" yaml:"quota,omitempty"` // upload+download bytes
	ExpireAt int64  `json:"expireAt,omitempty" yaml:"expire-at,omitempty"`
}

// UserLimitStatus is UserLimit with the current usage.
type UserLimitStatus struct {
	UserLimit
	Conns         int   `json:"conns"`
	Used          int64 `json:"used"`
	Remaining     int64 `json:"remaining"`
	Expired       bool  `json:"expired"`
	QuotaExceeded bool  `json:"quotaExceeded"`
}

type rateLimiter struct {
	rate    float64
	burst   float64
	tokens  float64
	last    time.Time
	mu      sync.Mutex
	changed chan struct{}
}

// wait blocks until n bytes may pass. A zero rate means unlimited. Only the
// token accounting is under the lock; the sleep is outside it, so changing or
// removing a limit never waits for a throttled connection. Tokens are reserved
// before sleeping, which keeps several connections of one user on the shared
// rate.
func (l *rateLimiter) wait(n int) {
	if l == nil || n <= 0 {
		return
	}
	l.mu.Lock()
	if l.rate <= 0 {
		l.mu.Unlock()
		return
	}
	now := time.Now()
	if l.last.IsZero() {
		l.last = now
		l.tokens = l.burst
	}
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now
	need := float64(n)
	if l.tokens >= need {
		l.tokens -= need
		l.mu.Unlock()
		return
	}
	wait := (need - l.tokens) / l.rate
	l.tokens -= need
	changed := l.changed
	l.mu.Unlock()

	timer := time.NewTimer(time.Duration(wait * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-changed:
	}
}

type limitState struct {
	limit UserLimit
	mu    sync.Mutex
	conns int
	used  int64
	up    *rateLimiter
	down  *rateLimiter
}

func (s *limitState) expired(now time.Time) bool {
	return s.limit.ExpireAt > 0 && now.Unix() >= s.limit.ExpireAt
}

// LimitManager holds the per-user policies and their usage. The policy table
// is published as one immutable map, so the read/write hot path does not take
// a lock.
type LimitManager struct {
	table atomic.Pointer[map[UserKey]*limitState]
	mu    sync.Mutex
}

// DefaultLimitManager is filled from user-limits and the controller API.
var DefaultLimitManager = newLimitManager()

func newLimitManager() *LimitManager {
	m := &LimitManager{}
	empty := make(map[UserKey]*limitState)
	m.table.Store(&empty)
	return m
}

func (m *LimitManager) lookup(key UserKey) *limitState {
	table := m.table.Load()
	if table == nil {
		return nil
	}
	return (*table)[key]
}

func newRateLimiter(bytesPerSecond int64) *rateLimiter {
	l := &rateLimiter{changed: make(chan struct{})}
	l.setRate(bytesPerSecond)
	return l
}

func (l *rateLimiter) setRate(bytesPerSecond int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.changed != nil {
		close(l.changed)
	}
	l.changed = make(chan struct{})
	if bytesPerSecond <= 0 {
		l.rate = 0
		l.burst = 0
		l.tokens = 0
		l.last = time.Time{}
		return
	}
	l.rate = float64(bytesPerSecond)
	l.burst = float64(bytesPerSecond) / 10
	if l.burst < 1 {
		l.burst = 1
	}
	l.tokens = 0
	l.last = time.Time{}
}

func (l *rateLimiter) ratePerSecond() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

func newLimitState(limit UserLimit) *limitState {
	return &limitState{
		limit: limit,
		up:    newRateLimiter(limit.UpBps),
		down:  newRateLimiter(limit.DownBps),
	}
}

// setLimit updates the policy of a live state without replacing the limiter
// objects, so a throttled relay never reads a half-updated pointer.
func (s *limitState) setLimit(limit UserLimit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit.UpBps != s.limit.UpBps {
		s.up.setRate(limit.UpBps)
	}
	if limit.DownBps != s.limit.DownBps {
		s.down.setRate(limit.DownBps)
	}
	s.limit = limit
}

// Replace sets the whole policy table. Usage of users that keep a policy is
// preserved.
func (m *LimitManager) Replace(limits []UserLimit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.table.Load()
	table := make(map[UserKey]*limitState, len(limits))
	for _, limit := range limits {
		key := UserKey{Inbound: limit.Inbound, User: limit.User}
		if key.User == "" {
			continue
		}
		if previous := (*old)[key]; previous != nil {
			previous.setLimit(limit)
			table[key] = previous
			continue
		}
		table[key] = newLimitState(limit)
	}
	m.table.Store(&table)
}

// Add or update one policy, keeping its usage.
func (m *LimitManager) Set(limit UserLimit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.table.Load()
	key := UserKey{Inbound: limit.Inbound, User: limit.User}
	table := make(map[UserKey]*limitState, len(*old)+1)
	for k, v := range *old {
		table[k] = v
	}
	if previous := table[key]; previous != nil {
		previous.setLimit(limit)
	} else {
		table[key] = newLimitState(limit)
	}
	m.table.Store(&table)
}

// Delete removes one policy.
func (m *LimitManager) Delete(inbound, user string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := UserKey{Inbound: inbound, User: user}
	old := m.table.Load()
	if _, ok := (*old)[key]; !ok {
		return false
	}
	table := make(map[UserKey]*limitState, len(*old))
	for k, v := range *old {
		if k != key {
			table[k] = v
		}
	}
	m.table.Store(&table)
	return true
}

// Admit checks whether a new connection of the user may start.
func (m *LimitManager) Admit(key UserKey) error {
	state := m.lookup(key)
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.expired(time.Now()) {
		return ErrUserLimitExpired
	}
	if state.limit.Quota > 0 && state.used >= state.limit.Quota {
		return ErrUserQuotaExceeded
	}
	if state.limit.MaxConns > 0 && state.conns >= state.limit.MaxConns {
		return ErrUserMaxConns
	}
	return nil
}

// Connect and Disconnect keep the live connection count of the user.
func (m *LimitManager) Connect(key UserKey) {
	if state := m.lookup(key); state != nil {
		state.mu.Lock()
		state.conns++
		state.mu.Unlock()
	}
}

func (m *LimitManager) Disconnect(key UserKey) {
	if state := m.lookup(key); state != nil {
		state.mu.Lock()
		if state.conns > 0 {
			state.conns--
		}
		state.mu.Unlock()
	}
}

// AddUsage counts payload bytes against the quota and reports whether the
// quota is now exhausted.
func (m *LimitManager) AddUsage(key UserKey, n int64) bool {
	state := m.lookup(key)
	if state == nil || n <= 0 {
		return false
	}
	state.mu.Lock()
	state.used += n
	exceeded := state.limit.Quota > 0 && state.used >= state.limit.Quota
	state.mu.Unlock()
	return exceeded
}

// Expired reports whether the user's policy has ended.
func (m *LimitManager) Expired(key UserKey) bool {
	state := m.lookup(key)
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.expired(time.Now())
}

// WaitUpload and WaitDownload throttle the user's relay.
func (m *LimitManager) WaitUpload(key UserKey, n int) {
	if state := m.lookup(key); state != nil {
		state.up.wait(n)
	}
}

func (m *LimitManager) WaitDownload(key UserKey, n int) {
	if state := m.lookup(key); state != nil {
		state.down.wait(n)
	}
}

// ResetQuota starts a new quota period for one user.
func (m *LimitManager) ResetQuota(inbound, user string) bool {
	state := m.lookup(UserKey{Inbound: inbound, User: user})
	if state == nil {
		return false
	}
	state.mu.Lock()
	state.used = 0
	state.mu.Unlock()
	return true
}

// Snapshot returns the policies with usage, optionally filtered.
func (m *LimitManager) Snapshot(inbound, user string) []UserLimitStatus {
	table := m.table.Load()
	if table == nil {
		return nil
	}
	statuses := make([]UserLimitStatus, 0, len(*table))
	for key, state := range *table {
		if inbound != "" && key.Inbound != inbound {
			continue
		}
		if user != "" && key.User != user {
			continue
		}
		state.mu.Lock()
		status := UserLimitStatus{
			UserLimit:     state.limit,
			Conns:         state.conns,
			Used:          state.used,
			Expired:       state.expired(time.Now()),
			QuotaExceeded: state.limit.Quota > 0 && state.used >= state.limit.Quota,
		}
		if state.limit.Quota > 0 {
			status.Remaining = state.limit.Quota - state.used
			if status.Remaining < 0 {
				status.Remaining = 0
			}
		}
		state.mu.Unlock()
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].Inbound != statuses[j].Inbound {
			return statuses[i].Inbound < statuses[j].Inbound
		}
		return statuses[i].User < statuses[j].User
	})
	return statuses
}
