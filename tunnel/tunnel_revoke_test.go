package tunnel_test

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// tunnelTestSession is a fixed C.InboundSession.
type tunnelTestSession struct{ revoked bool }

func (s *tunnelTestSession) Revoked() bool { return s.revoked }
func (s *tunnelTestSession) Bind(io.Closer, bool) (func(), bool) {
	return func() {}, !s.revoked
}

// dropTestPacket reports when the tunnel drops it: at once for a packet it
// refuses, or when the sender of a failed association is closed (after the
// dial has returned and given its slot back).
type dropTestPacket struct {
	limitTestPacket
	dropped chan struct{}
}

func (p *dropTestPacket) Drop() { close(p.dropped) }

func sendDropTestPacket(t *testing.T, metadata *C.Metadata) {
	t.Helper()
	packet := &dropTestPacket{
		limitTestPacket: limitTestPacket{
			data:   []byte("ping"),
			local:  net.UDPAddrFromAddrPort(netip.AddrPortFrom(metadata.SrcIP, metadata.SrcPort)),
			echoes: make(chan []byte, 1),
		},
		dropped: make(chan struct{}),
	}
	tunnel.Tunnel.HandleUDPPacket(packet, metadata)
	select {
	case <-packet.dropped:
	case <-time.After(5 * time.Second):
		t.Fatal("packet was neither dropped nor relayed")
	}
}

// S-4a: a UDP association whose dial fails after its slot was taken gives the
// slot back: with max-conns 1 the next association is admitted.
func TestUDPFailedDialReleasesSlot(t *testing.T) {
	setupTestTunnel()

	for _, tc := range []struct {
		name    string
		special string
		port    uint16
		listens int32
	}{
		{"resolveMetadata", "NO-SUCH-PROXY", 40101, 0},
		{"ListenPacketContext", "FAIL", 40102, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := statistic.UserKey{Inbound: "udp-fail-in", User: "udp-fail-" + tc.name}
			statistic.DefaultLimitManager.Set(statistic.UserLimit{Inbound: key.Inbound, User: key.User, MaxConns: 1})
			defer statistic.DefaultLimitManager.Delete(key.Inbound, key.User)

			before := failingProxy.listen.Load()
			sendDropTestPacket(t, &C.Metadata{
				NetWork:      C.UDP,
				Type:         C.VLESS,
				SrcIP:        netip.MustParseAddr("127.0.0.1"),
				SrcPort:      tc.port,
				DstIP:        netip.MustParseAddr("127.0.0.1"),
				DstPort:      9,
				InName:       key.Inbound,
				InUser:       key.User,
				SpecialProxy: tc.special,
			})
			if got := failingProxy.listen.Load() - before; got != tc.listens {
				t.Fatalf("failing proxy dialed %d times, want %d", got, tc.listens)
			}
			slot, err := statistic.DefaultLimitManager.Admit(key)
			if err != nil {
				t.Fatalf("slot of the failed association was not released: %v", err)
			}
			slot.Release()
		})
	}
}

// S-4b: the tunnel drops a connection or packet of a revoked user before
// dialing; a live user's one is dialed (control).
func TestTunnelDropsRevokedSessionBeforeDial(t *testing.T) {
	setupTestTunnel()

	for _, revoked := range []bool{true, false} {
		session := &tunnelTestSession{revoked: revoked}
		var want int32
		if !revoked {
			want = 1
		}

		// TCP is handled synchronously.
		before := failingProxy.dials.Load()
		client, server := net.Pipe()
		_ = client.Close()
		tunnel.Tunnel.HandleTCPConn(server, &C.Metadata{
			NetWork:      C.TCP,
			Type:         C.VLESS,
			SrcIP:        netip.MustParseAddr("127.0.0.1"),
			SrcPort:      40201,
			DstIP:        netip.MustParseAddr("127.0.0.1"),
			DstPort:      9,
			InName:       "revoke-in",
			InUser:       "revoke-user",
			InSession:    session,
			SpecialProxy: "FAIL",
		})
		if got := failingProxy.dials.Load() - before; got != want {
			t.Fatalf("revoked=%v: TCP dials = %d, want %d", revoked, got, want)
		}

		srcPort := uint16(40202)
		if !revoked {
			srcPort = 40203
		}
		before = failingProxy.listen.Load()
		sendDropTestPacket(t, &C.Metadata{
			NetWork:      C.UDP,
			Type:         C.VLESS,
			SrcIP:        netip.MustParseAddr("127.0.0.1"),
			SrcPort:      srcPort,
			DstIP:        netip.MustParseAddr("127.0.0.1"),
			DstPort:      9,
			InName:       "revoke-in",
			InUser:       "revoke-user",
			InSession:    session,
			SpecialProxy: "FAIL",
		})
		if got := failingProxy.listen.Load() - before; got != want {
			t.Fatalf("revoked=%v: UDP dials = %d, want %d", revoked, got, want)
		}
	}
}
