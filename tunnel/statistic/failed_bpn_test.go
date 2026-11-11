package statistic

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestBPNFailedConnectionsRingBufferAndEventBus(t *testing.T) {
	mgr := &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		failedTotal:   atomic.NewInt64(0),
		failedLimit:   3,
	}

	sub := eventbus.Subscribe(mustDialErrorMask(t), 8)
	defer sub.Close()

	for i := 0; i < 5; i++ {
		md := &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUN,
			SrcIP:   netip.MustParseAddr("198.18.0.1"),
			SrcPort: 50000 + uint16(i),
			Host:    "api.example.com",
			DstPort: 443,
			Process: "curl",
			InName:  "tun-in",
			InUser:  "secret-user-uuid-must-be-stripped",
		}
		fc := NewFailedConnection(
			md,
			time.Unix(1700000000+int64(i), 0),
			C.Chain{"exit-node", "AUTO"},
			C.Chain{"", ""},
			nil,
			errors.New("i/o timeout"),
			150*time.Millisecond,
		)
		mgr.RecordFailed(fc)
	}

	require.Equal(t, int64(5), mgr.FailedTotal())

	got := mgr.FailedConnections(0)
	require.Len(t, got, 3)
	require.Equal(t, uint16(50002), got[0].Metadata.SrcPort)
	require.Equal(t, uint16(50003), got[1].Metadata.SrcPort)
	require.Equal(t, uint16(50004), got[2].Metadata.SrcPort)
	for _, entry := range got {
		require.Empty(t, entry.Metadata.InUser, "InUser must never be retained in failed connections")
		require.Equal(t, int64(150), entry.DurationMs)
	}

	limited := mgr.FailedConnections(2)
	require.Len(t, limited, 2)
	require.Equal(t, uint16(50003), limited[0].Metadata.SrcPort)
	require.Equal(t, uint16(50004), limited[1].Metadata.SrcPort)

	// EventBus received dial.error events without user secrets.
	select {
	case ev := <-sub.C():
		require.Equal(t, eventbus.TypeDialError, ev.Type)
		de, ok := ev.Data.(eventbus.DialError)
		require.True(t, ok)
		require.Equal(t, "tcp", de.Network)
		require.Equal(t, "api.example.com:443", de.Destination)
		require.Equal(t, []string{"exit-node", "AUTO"}, de.Chains)
		require.Equal(t, "i/o timeout", de.Error)
	case <-time.After(2 * time.Second):
		t.Fatal("expected dial.error event on eventbus")
	}

	mgr.ClearFailed()
	require.Empty(t, mgr.FailedConnections(0))
	require.Equal(t, int64(5), mgr.FailedTotal(), "ClearFailed keeps cumulative counter")

	mgr.ResetStatistic()
	require.Equal(t, int64(0), mgr.FailedTotal())
}

func mustDialErrorMask(t *testing.T) eventbus.Mask {
	t.Helper()
	m, err := eventbus.ParseTypes(eventbus.TypeDialError)
	require.NoError(t, err)
	return m
}
