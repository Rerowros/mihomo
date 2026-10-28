package statistic

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// The client addresses of the inbound users: the online IP list of the Xray
// API (GetStatsOnline, GetStatsOnlineIpList, GetUsersStats), the ips of
// /traffic/users and /metrics, and the max-ips limit.
//
// The address is metadata.SrcIP of the tunnel connection: the TCP peer of the
// inbound (the real client with the PROXY protocol), the carrier connection for
// mux and XUDP streams. Behind a CDN (ws, xhttp, grpc) or a UDP/QUIC inbound
// behind a proxy every client has the address of the proxy, so max-ips is not
// safe there: one client takes the place of all. A trusted X-Forwarded-For is
// not used.
//
// Like Xray, loopback addresses are not recorded, an IPv4-mapped IPv6 address
// is the IPv4 address and an IPv6 address is counted whole.

// userIPRelease is how long an address whose last connection closed still
// takes a place in max-ips: a client that reconnects keeps its place, and a
// second client cannot take it in between. The online list does not use it:
// like Xray it shows only the addresses with open connections.
const userIPRelease = 60 * time.Second

// userIPSweepInterval is how often the expired addresses are dropped from the
// users nobody asks about; Admit and the readers drop them on the way.
const userIPSweepInterval = time.Minute

// ipReleaseWindow is the release window of the manager: userIPRelease unless
// a test set its own.
func (m *UserManager) ipReleaseWindow() time.Duration {
	if m.ipRelease > 0 {
		return m.ipRelease
	}
	return userIPRelease
}

// ipSlot is one address of a user on one inbound. The user name is global
// (like Xray's email), the inbound is kept so that revoking the user on one
// inbound forgets only the addresses of that inbound.
type ipSlot struct {
	inbound string
	ip      netip.Addr
}

type ipEntry struct {
	conns    int64
	lastSeen time.Time // the last new connection, Xray's lastSeen
	left     time.Time // when the last connection closed
	// drop marks an entry forgotten while it had open connections (the user
	// was revoked): it is not counted and goes away with its last connection.
	drop bool
}

// userIPs holds the addresses of one user name on all inbounds.
type userIPs struct {
	mu      sync.Mutex
	entries map[ipSlot]*ipEntry
	window  time.Duration // the release window of the manager
}

// trackedIP returns the address recorded for a connection from src.
func trackedIP(src netip.Addr) (netip.Addr, bool) {
	ip := src.Unmap().WithZone("")
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
		return netip.Addr{}, false
	}
	return ip, true
}

// FormatUserIP writes an address the way Xray does: IPv6 in brackets.
func FormatUserIP(ip netip.Addr) string {
	if ip.Is6() {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

// prune drops the addresses whose release window ended; the caller holds mu.
func (s *userIPs) prune(now time.Time) {
	for slot, entry := range s.entries {
		if entry.conns <= 0 && now.Sub(entry.left) >= s.window {
			delete(s.entries, slot)
		}
	}
}

// limitIPs returns the distinct addresses counted by max-ips (open or in the
// release window) and whether ip is one of them; the caller holds mu and has
// pruned.
func (s *userIPs) limitIPs(ip netip.Addr) (count int, holds bool) {
	seen := make(map[netip.Addr]struct{}, len(s.entries))
	for slot, entry := range s.entries {
		if entry.drop {
			continue
		}
		if slot.ip == ip {
			holds = true
		}
		seen[slot.ip] = struct{}{}
	}
	return len(seen), holds
}

// tryAcquire records a new connection from slot unless the user already has
// maxIPs other addresses (0 means no limit). The check and the record are one
// step under mu, so two inbounds of the user cannot both let a new address in.
// A nil set records nothing and admits.
func (s *userIPs) tryAcquire(slot ipSlot, maxIPs int, now time.Time) (*ipEntry, bool) {
	if s == nil {
		return nil, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	if maxIPs > 0 {
		if count, holds := s.limitIPs(slot.ip); !holds && count >= maxIPs {
			return nil, false
		}
	}
	entry := s.entries[slot]
	if entry == nil || entry.drop {
		// A forgotten entry keeps only its old connections: the new ones
		// start a fresh entry that its release cannot remove.
		entry = &ipEntry{}
		s.entries[slot] = entry
	}
	entry.conns++
	entry.lastSeen = now
	return entry, true
}

// release ends one connection of entry. The map is changed only while it
// still holds this entry, so the release of a forgotten one never touches the
// entry of a user that came back.
func (s *userIPs) release(slot ipSlot, entry *ipEntry, now time.Time) {
	if s == nil || entry == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.conns <= 0 {
		return
	}
	entry.conns--
	if entry.conns > 0 {
		return
	}
	entry.left = now
	if entry.drop && s.entries[slot] == entry {
		delete(s.entries, slot)
	}
}

// discard ends one connection of entry like release, but without a release
// window: the connection belonged to a revoked user, so its address must not
// hold a max-ips place of a user given the name again. An entry that never
// closed before goes away with its last connection; one that was already in
// its window keeps the old window instead of starting a new one.
func (s *userIPs) discard(slot ipSlot, entry *ipEntry) {
	if s == nil || entry == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.conns <= 0 {
		return
	}
	entry.conns--
	if entry.conns > 0 {
		return
	}
	if (entry.drop || entry.left.IsZero()) && s.entries[slot] == entry {
		delete(s.entries, slot)
	}
}

// ipSet returns the addresses of a user name; with create it makes them and
// starts the sweeper, which therefore runs only once an authenticated user
// connects from a non-loopback address. On a server that is the first user
// connection. A client build gets it only with allow-lan and authentication
// on its http/socks/mixed inbound, when a LAN device logs in: then it is one
// goroutine with a ticker once a minute. Other client builds never start it.
func (m *UserManager) ipSet(user string, create bool) *userIPs {
	m.mu.RLock()
	set := m.ipSets[user]
	m.mu.RUnlock()
	if set != nil || !create {
		return set
	}
	m.mu.Lock()
	if m.ipSets == nil {
		m.ipSets = make(map[string]*userIPs)
	}
	if set = m.ipSets[user]; set == nil {
		set = &userIPs{entries: make(map[ipSlot]*ipEntry), window: m.ipReleaseWindow()}
		m.ipSets[user] = set
	}
	m.mu.Unlock()
	m.ipSweeper.Do(func() {
		m.ipSweeperStarted.Store(true)
		interval := m.ipSweepInterval
		if interval <= 0 {
			interval = userIPSweepInterval
		}
		stop := make(chan struct{})
		m.mu.Lock()
		m.ipSweeperStop = stop
		m.mu.Unlock()
		go m.sweepIPs(interval, stop)
	})
	return set
}

// sweepIPs prunes all address sets every interval until stop is closed (only
// tests stop it; the managers of a running core live as long as it).
func (m *UserManager) sweepIPs(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			for _, set := range m.allIPSets() {
				set.mu.Lock()
				set.prune(now)
				set.mu.Unlock()
			}
		}
	}
}

func (m *UserManager) allIPSets() []*userIPs {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sets := make([]*userIPs, 0, len(m.ipSets))
	for _, set := range m.ipSets {
		sets = append(sets, set)
	}
	return sets
}

// ForgetIPs drops the addresses of a revoked user on one inbound, so a user
// given the name again (a new key) does not start with taken max-ips places.
// Addresses with open connections are marked and go with the last one.
func (m *UserManager) ForgetIPs(key UserKey) {
	set := m.ipSet(key.User, false)
	if set == nil {
		return
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	for slot, entry := range set.entries {
		if slot.inbound != key.Inbound {
			continue
		}
		if entry.conns <= 0 {
			delete(set.entries, slot)
		} else {
			entry.drop = true
		}
	}
}

// UserIP is one online address of a user.
type UserIP struct {
	IP       string `json:"ip"`       // IPv6 in brackets, like Xray
	LastSeen int64  `json:"lastSeen"` // unix seconds of the last new connection
	Conns    int64  `json:"conns"`
}

// OnlineIPs returns the addresses of user with open connections, on one
// inbound or, with an empty inbound, on all of them (Xray's per-email online
// map). Addresses in the release window are not online. It never creates a
// record.
func (m *UserManager) OnlineIPs(inbound, user string) []UserIP {
	set := m.ipSet(user, false)
	if set == nil {
		return nil
	}
	byIP := map[netip.Addr]*UserIP{}
	set.mu.Lock()
	for slot, entry := range set.entries {
		if entry.drop || entry.conns <= 0 || (inbound != "" && slot.inbound != inbound) {
			continue
		}
		ip := byIP[slot.ip]
		if ip == nil {
			ip = &UserIP{IP: FormatUserIP(slot.ip)}
			byIP[slot.ip] = ip
		}
		ip.Conns += entry.conns
		if seen := entry.lastSeen.Unix(); seen > ip.LastSeen {
			ip.LastSeen = seen
		}
	}
	set.mu.Unlock()
	if len(byIP) == 0 {
		return nil
	}
	ips := make([]UserIP, 0, len(byIP))
	for _, ip := range byIP {
		ips = append(ips, *ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].IP < ips[j].IP })
	return ips
}

// OnlineUsers returns the user names with at least one online address, sorted.
func (m *UserManager) OnlineUsers() []string {
	m.mu.RLock()
	names := make([]string, 0, len(m.ipSets))
	sets := make([]*userIPs, 0, len(m.ipSets))
	for name, set := range m.ipSets {
		names = append(names, name)
		sets = append(sets, set)
	}
	m.mu.RUnlock()
	var online []string
	for i, set := range sets {
		set.mu.Lock()
		for _, entry := range set.entries {
			if !entry.drop && entry.conns > 0 {
				online = append(online, names[i])
				break
			}
		}
		set.mu.Unlock()
	}
	sort.Strings(online)
	return online
}

// limitIPCount returns the addresses counted by max-ips for user.
func (m *UserManager) limitIPCount(user string) int {
	set := m.ipSet(user, false)
	if set == nil {
		return 0
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	set.prune(time.Now())
	count, _ := set.limitIPs(netip.Addr{})
	return count
}
