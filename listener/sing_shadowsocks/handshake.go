package sing_shadowsocks

import (
	"context"
	"net"

	authStore "github.com/metacubex/mihomo/listener/auth"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	M "github.com/metacubex/sing/common/metadata"
)

type handshakeConnKey struct{}

// withHandshakeConn arms the handshake deadline on the client connection
// (before simple-obfs) and remembers it in ctx for handshakeDone.
func withHandshakeConn(ctx context.Context, conn net.Conn) context.Context {
	authStore.SetHandshakeDeadline(conn)
	return context.WithValue(ctx, handshakeConnKey{}, conn)
}

// handshakeDone lifts the handshake deadline of the client connection (set
// in HandleConn) once the service has authenticated it and read its target,
// so a long-lived connection is never cut by it.
type handshakeDone struct {
	shadowsocks.Handler
}

func (h handshakeDone) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if raw, ok := ctx.Value(handshakeConnKey{}).(net.Conn); ok {
		authStore.ClearHandshakeDeadline(raw)
	}
	return h.Handler.NewConnection(ctx, conn, metadata)
}
