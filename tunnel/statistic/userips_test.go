package statistic

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIPLimitManager returns a limit manager with its own address table.
func newIPLimitManager() *LimitManager {
	m := newLimitManager()
	m.users = &UserManager{users: make(map[UserKey]*userCounters)}
	return m
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func onlineIPStrings(m *LimitManager, inbound, user string) []string {
	var ips []string
	for _, ip := range m.userManager().OnlineIPs(inbound, user) {
		ips = append(ips, ip.IP)
	}
	return ips
}

func shortIPRelease(t *testing.T, d time.Duration) {
	old := userIPRelease
	userIPRelease = d
	t.Cleanup(func() { userIPRelease = old })
}

// max-ips=1: a second address is refused, the same address passes; after its
// last connection the address keeps the place for the release window, then
// another address passes.
func TestMaxIPsWindow(t *testing.T) {
	shortIPRelease(t, 200*time.Millisecond)
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxIPs: 1})

	a1, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	_, err = m.AdmitFrom(key, addr("198.51.100.2"))
	require.ErrorIs(t, err, ErrUserMaxIPs)
	a2, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)

	a1.Release()
	a2.Release()
	assert.Empty(t, onlineIPStrings(m, "", "u"), "online list keeps an address without connections")
	_, err = m.AdmitFrom(key, addr("198.51.100.2"))
	require.ErrorIs(t, err, ErrUserMaxIPs, "the address that just left lost its place at once")
	assert.Equal(t, 1, m.Snapshot("in", "u")[0].IPs)

	time.Sleep(250 * time.Millisecond)
	b, err := m.AdmitFrom(key, addr("198.51.100.2"))
	require.NoError(t, err, "the release window did not end")
	b.Release()
}

// The limit is per user name on all inbounds.
func TestMaxIPsAcrossInbounds(t *testing.T) {
	m := newIPLimitManager()
	m.Set(UserLimit{Inbound: "in1", User: "u", MaxIPs: 1})
	m.Set(UserLimit{Inbound: "in2", User: "u", MaxIPs: 1})

	a, err := m.AdmitFrom(UserKey{Inbound: "in1", User: "u"}, addr("198.51.100.1"))
	require.NoError(t, err)
	defer a.Release()
	_, err = m.AdmitFrom(UserKey{Inbound: "in2", User: "u"}, addr("198.51.100.2"))
	require.ErrorIs(t, err, ErrUserMaxIPs)
	b, err := m.AdmitFrom(UserKey{Inbound: "in2", User: "u"}, addr("198.51.100.1"))
	require.NoError(t, err)
	defer b.Release()
}

// Parallel connections from different new addresses cannot all pass.
func TestMaxIPsParallel(t *testing.T) {
	m := newIPLimitManager()
	m.Set(UserLimit{Inbound: "in1", User: "u", MaxIPs: 1})
	m.Set(UserLimit{Inbound: "in2", User: "u", MaxIPs: 1})
	var passed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			inbound := "in1"
			if i%2 == 1 {
				inbound = "in2"
			}
			ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
			if _, err := m.AdmitFrom(UserKey{Inbound: inbound, User: "u"}, ip); err == nil {
				passed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	assert.Equal(t, int32(1), passed.Load())
}

// A key given again after a revoke: forgetting the addresses during open
// connections, then a new connection from the same address, then the release
// of the old one must not remove the new entry.
func TestForgetIPsReissueRace(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxIPs: 1})

	old, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	m.userManager().ForgetIPs(key)
	assert.Empty(t, onlineIPStrings(m, "", "u"), "forgotten address still online")

	fresh, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	old.Release()
	assert.Equal(t, []string{"198.51.100.1"}, onlineIPStrings(m, "", "u"), "old release removed the new entry")
	assert.Equal(t, 1, m.Snapshot("in", "u")[0].IPs)
	fresh.Release()
	old.Release()

	// Forgotten without open connections: no release window, a new
	// address passes at once.
	m.userManager().ForgetIPs(key)
	b, err := m.AdmitFrom(key, addr("198.51.100.2"))
	require.NoError(t, err)
	b.Release()
}

// A forgotten entry with open connections leaves with its last one and does
// not hold a max-ips place meanwhile; other inbounds keep their addresses.
func TestForgetIPsOpenConnections(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxIPs: 2})
	old, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	other, err := m.AdmitFrom(UserKey{Inbound: "in2", User: "u"}, addr("198.51.100.9"))
	require.NoError(t, err)
	defer other.Release()

	m.userManager().ForgetIPs(key)
	assert.Equal(t, []string{"198.51.100.9"}, onlineIPStrings(m, "", "u"))
	b, err := m.AdmitFrom(key, addr("198.51.100.2"))
	require.NoError(t, err, "a forgotten address kept its place")
	b.Release()
	old.Release()
	set := m.userManager().ipSet("u", false)
	set.mu.Lock()
	_, kept := set.entries[ipSlot{inbound: "in", ip: addr("198.51.100.1")}]
	set.mu.Unlock()
	assert.False(t, kept, "forgotten entry stayed after its last connection")
}

func TestUserIPMappedAndIPv6(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxIPs: 2})

	a, err := m.AdmitFrom(key, addr("::ffff:198.51.100.1"))
	require.NoError(t, err)
	defer a.Release()
	b, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	defer b.Release()
	c, err := m.AdmitFrom(key, addr("2001:db8::1"))
	require.NoError(t, err, "the mapped and the plain IPv4 address took two places")
	defer c.Release()

	ips := m.userManager().OnlineIPs("in", "u")
	require.Len(t, ips, 2)
	assert.Equal(t, "198.51.100.1", ips[0].IP)
	assert.Equal(t, int64(2), ips[0].Conns)
	assert.Equal(t, "[2001:db8::1]", ips[1].IP)
	assert.NotZero(t, ips[1].LastSeen)
}

// Loopback and missing addresses are not recorded and not limited.
func TestUserIPLoopbackNotOnline(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxIPs: 1})
	for _, ip := range []netip.Addr{addr("127.0.0.1"), addr("127.0.0.2"), addr("::1"), {}} {
		a, err := m.AdmitFrom(key, ip)
		require.NoError(t, err, ip)
		defer a.Release()
	}
	assert.Empty(t, onlineIPStrings(m, "", "u"))
	assert.Empty(t, m.userManager().OnlineUsers())
}

// A connection refused by max-conns records no address.
func TestMaxConnsRejectRecordsNoIP(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxConns: 1})
	a, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	defer a.Release()
	_, err = m.AdmitFrom(key, addr("198.51.100.2"))
	require.ErrorIs(t, err, ErrUserMaxConns)
	assert.Equal(t, []string{"198.51.100.1"}, onlineIPStrings(m, "", "u"))
	assert.Equal(t, 1, m.Snapshot("in", "u")[0].IPs)
}

// A connection refused by max-ips takes no max-conns slot.
func TestMaxIPsRejectTakesNoSlot(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxConns: 2, MaxIPs: 1})
	a, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	defer a.Release()
	for i := 0; i < 3; i++ {
		_, err = m.AdmitFrom(key, addr("198.51.100.2"))
		require.ErrorIs(t, err, ErrUserMaxIPs)
	}
	assert.Equal(t, 1, m.Snapshot("in", "u")[0].Conns)
	b, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err, "a max-ips rejection took a slot")
	defer b.Release()
	assert.Equal(t, uint64(3), m.Rejections()[3])
	assert.Equal(t, RejectMaxIPs, RejectReasons[3])
}

// Lowering max-ips keeps the open connections and their addresses; only new
// addresses are refused.
func TestMaxIPsLowered(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxIPs: 3})
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		a, err := m.AdmitFrom(key, addr(ip))
		require.NoError(t, err)
		defer a.Release()
	}
	m.Set(UserLimit{Inbound: "in", User: "u", MaxIPs: 1})
	assert.Len(t, onlineIPStrings(m, "", "u"), 3)
	assert.Equal(t, 3, m.Snapshot("in", "u")[0].Conns)
	_, err := m.AdmitFrom(key, addr("198.51.100.4"))
	require.ErrorIs(t, err, ErrUserMaxIPs)
	b, err := m.AdmitFrom(key, addr("198.51.100.2"))
	require.NoError(t, err)
	defer b.Release()
}

// A user without a policy still has its addresses recorded for the API.
func TestUserIPsWithoutPolicy(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "free"}
	a, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	assert.Equal(t, []string{"198.51.100.1"}, onlineIPStrings(m, "in", "free"))
	assert.Equal(t, []string{"free"}, m.userManager().OnlineUsers())
	a.Release()
	a.Release()
	assert.Empty(t, onlineIPStrings(m, "in", "free"))
}

// The release-window sweeper starts only once an address is recorded: a
// client build (no inbound users) or users without a real address never get
// the goroutine.
func TestIPSweeperStartsOnFirstAddress(t *testing.T) {
	m := newIPLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	for _, ip := range []netip.Addr{{}, addr("127.0.0.1"), addr("::1")} {
		a, err := m.AdmitFrom(key, ip)
		require.NoError(t, err)
		a.Release()
	}
	_, _ = m.Admit(key)
	_ = m.Snapshot("", "")
	_ = m.userManager().OnlineIPs("", "u")
	_ = m.userManager().OnlineUsers()
	m.userManager().ForgetIPs(key)
	assert.False(t, m.userManager().ipSweeperStarted.Load(), "sweeper started without an address")
	assert.Nil(t, m.userManager().ipSet("u", false), "readers created a record")

	a, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	a.Release()
	assert.True(t, m.userManager().ipSweeperStarted.Load())
}

func TestIPSweeperPrunes(t *testing.T) {
	shortIPRelease(t, 10*time.Millisecond)
	oldInterval := userIPSweepInterval
	userIPSweepInterval = 20 * time.Millisecond
	t.Cleanup(func() { userIPSweepInterval = oldInterval })
	m := newIPLimitManager()
	a, err := m.AdmitFrom(UserKey{Inbound: "in", User: "u"}, addr("198.51.100.1"))
	require.NoError(t, err)
	a.Release()
	set := m.userManager().ipSet("u", false)
	require.Eventually(t, func() bool {
		set.mu.Lock()
		defer set.mu.Unlock()
		return len(set.entries) == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestMaxIPsRejectedEvent(t *testing.T) {
	const inbound = "events-maxips-in"
	m := newIPLimitManager()
	key := UserKey{Inbound: inbound, User: "eve"}
	m.Set(UserLimit{Inbound: inbound, User: "eve", MaxIPs: 1})
	s := subscribe(t, eventbus.TypeUserLimit, 16)

	a, err := m.AdmitFrom(key, addr("198.51.100.1"))
	require.NoError(t, err)
	defer a.Release()
	_, err = m.AdmitFrom(key, addr("2001:db8::5"))
	require.ErrorIs(t, err, ErrUserMaxIPs)
	e := nextEvent(t, s, inbound)
	assert.Equal(t, eventbus.UserLimit{
		Inbound: inbound, User: "eve", Reason: RejectMaxIPs, Action: eventbus.LimitRejected, Remote: "[2001:db8::5]",
	}, e.Data)
}
