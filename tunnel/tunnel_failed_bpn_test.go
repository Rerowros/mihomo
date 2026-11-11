package tunnel_test

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/require"
)

func TestBPNTunnelRecordsFailedDialsAndSkipsReject(t *testing.T) {
	setupTestTunnel()
	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
		"REJECT": adapter.NewProxy(outbound.NewReject()),
		"FAIL":   failingProxy,
	}, nil)
	statistic.DefaultManager.ResetStatistic()
	t.Cleanup(func() {
		statistic.DefaultManager.ResetStatistic()
	})

	// 1. Failed TCP dial via FAIL outbound is recorded with chain and error.
	cClient, cTunnel := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, cClient)
		_ = cClient.Close()
	}()
	tunnel.Tunnel.HandleTCPConn(cTunnel, &C.Metadata{
		NetWork:      C.TCP,
		Host:         "unreachable.example.com",
		DstPort:      443,
		SrcIP:        netip.MustParseAddr("127.0.0.1"),
		SrcPort:      55001,
		SpecialProxy: "FAIL",
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TCP conn was not closed after failed dial")
	}

	require.Eventually(t, func() bool {
		return statistic.DefaultManager.FailedTotal() == 1
	}, 2*time.Second, 20*time.Millisecond)
	entries := statistic.DefaultManager.FailedConnections(10)
	require.Len(t, entries, 1)
	require.Equal(t, "unreachable.example.com", entries[0].Metadata.Host)
	require.Equal(t, C.Chain{"DIRECT"}, entries[0].Chain)
	require.Contains(t, entries[0].Error, "reject loopback connection")

	// 2. Failed UDP dial via FAIL outbound is also recorded.
	sendDropTestPacket(t, &C.Metadata{
		NetWork:      C.UDP,
		DstIP:        netip.MustParseAddr("127.0.0.1"),
		DstPort:      5353,
		SrcIP:        netip.MustParseAddr("127.0.0.1"),
		SrcPort:      55002,
		SpecialProxy: "FAIL",
	})
	require.Eventually(t, func() bool {
		return statistic.DefaultManager.FailedTotal() == 2
	}, 2*time.Second, 20*time.Millisecond)

	// 3. Intentional REJECT policy decision does NOT pollute failed connection logs.
	rClient, rTunnel := net.Pipe()
	rDone := make(chan struct{})
	go func() {
		defer close(rDone)
		_, _ = io.Copy(io.Discard, rClient)
		_ = rClient.Close()
	}()
	tunnel.Tunnel.HandleTCPConn(rTunnel, &C.Metadata{
		NetWork:      C.TCP,
		Host:         "ads.example.com",
		DstPort:      443,
		SrcIP:        netip.MustParseAddr("127.0.0.1"),
		SrcPort:      55003,
		SpecialProxy: "REJECT",
	})
	select {
	case <-rDone:
	case <-time.After(5 * time.Second):
		t.Fatal("REJECT TCP conn was not closed")
	}
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int64(2), statistic.DefaultManager.FailedTotal())
}
