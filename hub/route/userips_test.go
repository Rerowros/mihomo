package route

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user given a new key through the runtime user table starts without the
// max-ips places of the old key: the addresses in the release window are
// dropped at once, the ones with open connections with their last one.
func TestRevokeForgetsUserIPs(t *testing.T) {
	const uuidA, uuidB = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	name := fmt.Sprintf("ips-vless-%d", time.Now().UnixNano())
	// max-ips counts the user name on all inbounds: a name of its own keeps
	// other tests (and -count runs) out.
	alice := "alice-" + name
	startRouteVless(t, name, []inbound.VlessUser{{Username: alice, UUID: uuidA}})
	key := statistic.UserKey{Inbound: name, User: alice}
	statistic.DefaultLimitManager.Set(statistic.UserLimit{Inbound: name, User: alice, MaxIPs: 2})
	t.Cleanup(func() { statistic.DefaultLimitManager.Delete(name, alice) })

	left, err := statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("198.51.100.1"))
	require.NoError(t, err)
	left.Release() // in the release window now
	open, err := statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("198.51.100.2"))
	require.NoError(t, err)
	_, err = statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("198.51.100.3"))
	require.ErrorIs(t, err, statistic.ErrUserMaxIPs)

	change, err := listener.SetInboundUsers(name, []C.InboundUser{{Username: alice, UUID: uuidB}})
	require.NoError(t, err)
	require.Equal(t, []string{alice}, change.Revoked)
	assert.Empty(t, statistic.DefaultUserManager.OnlineIPs(name, alice))

	a, err := statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("198.51.100.3"))
	require.NoError(t, err, "the revoked key kept its places")
	defer a.Release()
	b, err := statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("198.51.100.2"))
	require.NoError(t, err)
	defer b.Release()
	open.Release()
	assert.Len(t, statistic.DefaultUserManager.OnlineIPs(name, alice), 2, "the old release touched the new entries")
}

// GET /traffic/users lists the online addresses of the user on the inbound.
func TestTrafficUsersIPs(t *testing.T) {
	name := fmt.Sprintf("ips-traffic-%d", time.Now().UnixNano())
	key := statistic.UserKey{Inbound: name, User: "bob"}
	statistic.DefaultUserManager.PushUploaded(key, 1)
	a, err := statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("2001:db8::2"))
	require.NoError(t, err)
	defer a.Release()

	rec := get(router(false, testSecret, "", Cors{}), "/traffic/users?inbound="+name, testSecret)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var stats []statistic.UserStat
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &stats))
	require.Len(t, stats, 1)
	require.Len(t, stats[0].IPs, 1)
	assert.Equal(t, "[2001:db8::2]", stats[0].IPs[0].IP)
	assert.Equal(t, int64(1), stats[0].IPs[0].Conns)
	assert.NotZero(t, stats[0].IPs[0].LastSeen)
}

// A max-ips rejection reaches the stream with its reason and address.
func TestEventsMaxIPs(t *testing.T) {
	name := fmt.Sprintf("ips-events-%d", time.Now().UnixNano())
	carol := "carol-" + name
	key := statistic.UserKey{Inbound: name, User: carol}
	statistic.DefaultLimitManager.Set(statistic.UserLimit{Inbound: name, User: carol, MaxIPs: 1})
	t.Cleanup(func() { statistic.DefaultLimitManager.Delete(name, carol) })

	srv := eventsServer(t)
	r, closeStream := openEvents(t, srv, "?types=user.limit", "")
	defer closeStream()
	a, err := statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("198.51.100.1"))
	require.NoError(t, err)
	defer a.Release()
	_, err = statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr("198.51.100.9"))
	require.ErrorIs(t, err, statistic.ErrUserMaxIPs)
	e := readEvent(t, r)
	require.Equal(t, eventbus.TypeUserLimit, e.Type)
	assert.JSONEq(t, `{"inbound":"`+name+`","user":"`+carol+`","reason":"max-ips","action":"rejected","remote":"198.51.100.9"}`, string(e.Data))
}
