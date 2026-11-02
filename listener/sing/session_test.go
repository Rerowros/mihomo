package sing

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sing/common/auth"
	M "github.com/metacubex/sing/common/metadata"
)

type revokedTestSession struct{}

func (revokedTestSession) Revoked() bool                       { return true }
func (revokedTestSession) Bind(io.Closer, bool) (func(), bool) { return func() {}, false }

type sessionTestTunnel struct{ tcp int }

func (t *sessionTestTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) {
	t.tcp++
	_ = conn.Close()
}
func (t *sessionTestTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (t *sessionTestTunnel) NatTable() C.NatTable                     { return nil }

// S-5: the session is looked up only for an authenticated user, as in
// getAdditions: a revoked user's stream is refused, a connection without a
// user (TUN, mixed) is not checked against a session.
func TestNewConnectionSessionOnlyForUser(t *testing.T) {
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 9)
	for _, withUser := range []bool{true, false} {
		tunnel := &sessionTestTunnel{}
		h := &ListenerHandler{ListenerConfig: ListenerConfig{Tunnel: tunnel, Type: C.VLESS}}
		ctx := WithInboundSession(context.Background(), revokedTestSession{})
		if withUser {
			ctx = auth.ContextWithUser(ctx, "alice")
		}
		client, server := net.Pipe()
		err := h.NewConnection(ctx, server, M.Metadata{Destination: destination})
		_ = client.Close()
		if withUser {
			if err != C.ErrInboundUserRevoked || tunnel.tcp != 0 {
				t.Fatalf("revoked user: err = %v, tunnel saw %d", err, tunnel.tcp)
			}
		} else if err != nil || tunnel.tcp != 1 {
			t.Fatalf("no user: err = %v, tunnel saw %d", err, tunnel.tcp)
		}
	}
}
