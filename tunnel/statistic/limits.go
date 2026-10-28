package statistic

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
)

var (
	ErrUserLimitExpired  = errors.New("user expired")
	ErrUserQuotaExceeded = errors.New("user quota exceeded")
	ErrUserMaxConns      = errors.New("user connection limit reached")
	ErrUserMaxIPs        = errors.New("user address limit reached")
)

// UserLimit is the policy of one inbound user. Zero means "no limit".
type UserLimit struct {
	Inbound  string `json:"inbound" yaml:"inbound"`
	User     string `json:"user" yaml:"user"`
	MaxConns int    `json:"maxConns,omitempty" yaml:"max-conns,omitempty"`
	// MaxIPs is the number of client addresses of the user name on all
	// inbounds at once; see userips.go for what an address is and why it is
	// not safe behind a CDN. Lowering it does not close open connections.
	MaxIPs   int   `json:"maxIPs,omitempty" yaml:"max-ips,omitempty"`
	UpBps    int64 `json:"upBps,omitempty" yaml:"up-bps,omitempty"`
	DownBps  int64 `json:"downBps,omitempty" yaml:"down-bps,omitempty"`
	Quota    int64 `json:"quota,omitempty" yaml:"quota,omitempty"` // upload+download bytes
	ExpireAt int64 `json:"expireAt,omitempty" yaml:"expire-at,omitempty"`
}

// UserLimitStatus is UserLimit with the current usage.
type UserLimitStatus struct {
	UserLimit
	Conns         int   `json:"conns"`
	IPs           int   `json:"ips"` // addresses counted by max-ips, with the release window
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

	// The event stream state, guarded by mu: expiry is reported once per
	// expire-at, rejections at most once a second with the count of the
	// ones in between.
	expiredReported bool
	lastReject      time.Time
	suppressed      int64
}

// release lifts the rate limits of a state that left the table: relays
// sleeping on it wake up and go on without a limit.
func (s *limitState) release() {
	s.up.setRate(0)
	s.down.setRate(0)
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

	rejectedExpired  atomic.Uint64
	rejectedQuota    atomic.Uint64
	rejectedMaxConns atomic.Uint64
	rejectedMaxIPs   atomic.Uint64

	// users holds the client addresses; nil means DefaultUserManager.
	users *UserManager
}

// Reasons of a refused connection, in /metrics and on the event stream.
const (
	RejectExpired  = "expired"
	RejectQuota    = "quota"
	RejectMaxConns = "max-conns"
	RejectMaxIPs   = "max-ips"
)

// RejectReasons lists the reasons in the order of Rejections.
var RejectReasons = []string{RejectExpired, RejectQuota, RejectMaxConns, RejectMaxIPs}

// Rejections returns the number of connections Admit refused since start, in
// the order of RejectReasons.
func (m *LimitManager) Rejections() []uint64 {
	return []uint64{m.rejectedExpired.Load(), m.rejectedQuota.Load(), m.rejectedMaxConns.Load(), m.rejectedMaxIPs.Load()}
}

func (m *LimitManager) userManager() *UserManager {
	if m.users != nil {
		return m.users
	}
	return DefaultUserManager
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
	if limit.ExpireAt != s.limit.ExpireAt {
		s.expiredReported = false
	}
	s.limit = limit
}

// rejectEventInterval is how often the rejections of one user are reported.
var rejectEventInterval = time.Second

// rejectEvent decides, under s.mu, whether a rejection is reported now and
// with how many earlier ones folded in; ok is false while nobody listens.
func (s *limitState) rejectEvent(now time.Time) (suppressed int64, ok bool) {
	if !eventbus.Enabled(eventbus.TypeUserLimit) {
		return 0, false
	}
	if !s.lastReject.IsZero() && now.Sub(s.lastReject) < rejectEventInterval {
		s.suppressed++
		return 0, false
	}
	s.lastReject = now
	suppressed, s.suppressed = s.suppressed, 0
	return suppressed, true
}

// publishLimit reports a user whose connections are closed (quota used up,
// expired) or whose new connection was refused; remote is the refused address
// of a max-ips rejection.
func publishLimit(key UserKey, reason, action string, suppressed int64, remote string) {
	eventbus.Publish(eventbus.TypeUserLimit, eventbus.UserLimit{
		Inbound: key.Inbound, User: key.User, Reason: reason, Action: action, Suppressed: suppressed, Remote: remote,
	})
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
	for key, state := range *old {
		if table[key] != state {
			state.release()
		}
	}
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
	state, ok := (*old)[key]
	if !ok {
		return false
	}
	table := make(map[UserKey]*limitState, len(*old))
	for k, v := range *old {
		if k != key {
			table[k] = v
		}
	}
	m.table.Store(&table)
	state.release()
	return true
}

// Admission is the connection slot of one user, taken by Admit. Release
// returns it to the policy state it was taken from, so a policy deleted and set
// again does not count the old connections. It also holds the client address
// of the connection, which goes into the release window on Release. A nil
// Admission is valid: the user has no policy and no recorded address.
type Admission struct {
	state *limitState // nil without a policy
	ips   *userIPs    // nil without a recorded address
	slot  ipSlot
	entry *ipEntry
	once  sync.Once
}

// Release frees the slot; calls after the first are no-ops.
func (a *Admission) Release() {
	a.free(false)
}

// ReleaseFor is Release for a connection of session: when the session was
// revoked, the address is dropped without a release window. A connection that
// passed the revoke check of the tunnel, then the forgetting of the revoked
// addresses, then Admit, and is only refused afterwards would otherwise keep a
// max-ips place of the user given the name again for the whole window.
func (a *Admission) ReleaseFor(session C.InboundSession) {
	a.free(session != nil && session.Revoked())
}

func (a *Admission) free(revoked bool) {
	if a == nil {
		return
	}
	a.once.Do(func() {
		if a.state != nil {
			a.state.mu.Lock()
			if a.state.conns > 0 {
				a.state.conns--
			}
			a.state.mu.Unlock()
		}
		if revoked {
			a.ips.discard(a.slot, a.entry)
		} else {
			a.ips.release(a.slot, a.entry, time.Now())
		}
	})
}

// Admit checks whether a new connection of the user may start and, if so,
// takes a slot under the same lock, so parallel connections cannot all pass a
// max-conns check. The slot is taken for every policy (not only max-conns), so
// /limits shows the live count and a max-conns added later sees the existing
// connections.
func (m *LimitManager) Admit(key UserKey) (*Admission, error) {
	return m.AdmitFrom(key, netip.Addr{})
}

// AdmitFrom is Admit for a connection from src: the address is recorded for
// the online list and checked against max-ips together with the slot. A
// connection refused by max-conns records no address, one refused by max-ips
// takes no slot. Lock order: state.mu, then the address set of the user.
func (m *LimitManager) AdmitFrom(key UserKey, src netip.Addr) (*Admission, error) {
	var ips *userIPs
	slot := ipSlot{inbound: key.Inbound}
	if ip, ok := trackedIP(src); ok {
		slot.ip = ip
		ips = m.userManager().ipSet(key.User, true)
	}
	state := m.lookup(key)
	if state == nil {
		if ips == nil {
			return nil, nil
		}
		entry, _ := ips.tryAcquire(slot, 0, time.Now())
		return &Admission{ips: ips, slot: slot, entry: entry}, nil
	}
	state.mu.Lock()
	now := time.Now()
	var reason, remote string
	var err error
	switch {
	case state.expired(now):
		m.rejectedExpired.Add(1)
		reason, err = RejectExpired, ErrUserLimitExpired
	case state.limit.Quota > 0 && state.used >= state.limit.Quota:
		m.rejectedQuota.Add(1)
		reason, err = RejectQuota, ErrUserQuotaExceeded
	case state.limit.MaxConns > 0 && state.conns >= state.limit.MaxConns:
		m.rejectedMaxConns.Add(1)
		reason, err = RejectMaxConns, ErrUserMaxConns
	default:
		entry, ok := ips.tryAcquire(slot, state.limit.MaxIPs, now)
		if !ok {
			m.rejectedMaxIPs.Add(1)
			reason, err, remote = RejectMaxIPs, ErrUserMaxIPs, FormatUserIP(slot.ip)
			break
		}
		state.conns++
		state.mu.Unlock()
		return &Admission{state: state, ips: ips, slot: slot, entry: entry}, nil
	}
	suppressed, report := state.rejectEvent(now)
	state.mu.Unlock()
	if report {
		publishLimit(key, reason, eventbus.LimitRejected, suppressed, remote)
	}
	return nil, err
}

// AddUsage counts payload bytes against the quota and reports whether the
// quota is now exhausted.
func (m *LimitManager) AddUsage(key UserKey, n int64) bool {
	state := m.lookup(key)
	if state == nil || n <= 0 {
		return false
	}
	state.mu.Lock()
	before := state.used
	state.used += n
	exceeded := state.limit.Quota > 0 && state.used >= state.limit.Quota
	crossed := exceeded && before < state.limit.Quota
	state.mu.Unlock()
	if crossed && eventbus.Enabled(eventbus.TypeUserLimit) {
		publishLimit(key, RejectQuota, eventbus.LimitClosed, 0, "")
	}
	return exceeded
}

// Expired reports whether the user's policy has ended.
func (m *LimitManager) Expired(key UserKey) bool {
	state := m.lookup(key)
	if state == nil {
		return false
	}
	state.mu.Lock()
	expired := state.expired(time.Now())
	first := expired && !state.expiredReported
	if first {
		state.expiredReported = true
	}
	state.mu.Unlock()
	if first && eventbus.Enabled(eventbus.TypeUserLimit) {
		publishLimit(key, RejectExpired, eventbus.LimitClosed, 0, "")
	}
	return expired
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
		status.IPs = m.userManager().limitIPCount(key.User)
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
