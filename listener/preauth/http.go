// Package preauth holds the pre-authentication limits shared by inbound
// listeners.
package preauth

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
)

type firstRequestKey struct{}

type firstRequestGuard struct {
	conn  net.Conn
	timer *time.Timer
	done  atomic.Bool
}

// expire closes a connection that sent no request in time.
func (g *firstRequestGuard) expire() {
	if g.done.CompareAndSwap(false, true) {
		_ = g.conn.Close()
	}
}

// GuardFirstRequest closes every connection accepted by srv that does not
// deliver its first request to srv.Handler within timeout of being accepted.
// It must be called after srv.Handler is set and before srv.Serve.
//
// ReadHeaderTimeout alone does not bound the time before the first request:
// with Protocols.UnencryptedHTTP2 the server first waits for the h2c preface
// with no deadline at all (plain conns, and TLS conns that did not negotiate
// h2: the server clears the TLS handshake deadline before that wait), and an
// h2 conn may send its preface and settings and then never open a stream.
// A timer, unlike a read deadline, cannot be reset by the server and also
// bounds a client that trickles bytes.
//
// Once a request reaches the handler the guard is gone for good: long gRPC
// streams, xhttp downloads and uploads, and conns idle between requests are
// then governed by the server's own timeouts (IdleTimeout, h2 idle handling)
// and by the handshake deadline of the proxy protocol behind the handler.
func GuardFirstRequest(srv *http.Server, timeout time.Duration) {
	next := srv.Handler
	connContext := srv.ConnContext
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if connContext != nil {
			ctx = connContext(ctx, c)
		}
		g := &firstRequestGuard{conn: c}
		g.timer = time.AfterFunc(timeout, g.expire)
		return context.WithValue(ctx, firstRequestKey{}, g)
	}
	// The request context of HTTP/1, h2 and h2c requests derives from the
	// context returned by ConnContext.
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g, _ := r.Context().Value(firstRequestKey{}).(*firstRequestGuard); g != nil && g.done.CompareAndSwap(false, true) {
			g.timer.Stop()
		}
		next.ServeHTTP(w, r)
	})
}
