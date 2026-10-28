package sing

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// Limits of one sing-mux (smux, yamux, h2mux) session on the server.
//
// sing-mux starts a goroutine per accepted stream, which then waits, with no
// deadline, for the stream request (network and destination). Without a cap
// one authenticated client could open streams until the process runs out of
// memory, and a stream that never sends its request would hold its goroutine
// for the life of the session.
//
//   - muxMaxStreams: streams of one session counted from accept until their
//     handler returns; a stream beyond it is closed as soon as it is accepted.
//     1024 is far above what one client multiplexes (sing-box and mihomo
//     clients default to a few streams per connection, a phone in
//     single-connection mode has a few hundred).
//   - muxHandshakeTimeout: a stream must send its request within it, else it
//     is closed. The value matches the VLESS and Trojan listeners.
//
// Variables only so that tests can lower them.
var (
	muxMaxStreams       int32 = 1024
	muxHandshakeTimeout       = 15 * time.Second
)

type muxSessionKey struct{}
type muxStreamKey struct{}

type muxSession struct {
	streams atomic.Int32
}

type muxStream struct {
	conn    net.Conn
	session *muxSession
	timer   *time.Timer
	started atomic.Bool
}

func (s *muxStream) release() { s.session.streams.Add(-1) }

// expire closes a stream that did not reach the handler in time.
func (s *muxStream) expire() {
	if s.started.CompareAndSwap(false, true) {
		_ = s.conn.Close()
		s.release()
	}
}

// withMuxSession marks ctx as the context of a new sing-mux session.
func withMuxSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, muxSessionKey{}, &muxSession{})
}

// newMuxStreamContext is the sing-mux NewStreamContext hook, called in the
// accept loop of a session for each new stream.
func newMuxStreamContext(ctx context.Context, stream net.Conn) context.Context {
	session, _ := ctx.Value(muxSessionKey{}).(*muxSession)
	if session == nil {
		return ctx
	}
	if session.streams.Add(1) > muxMaxStreams {
		session.streams.Add(-1)
		_ = stream.Close()
		return context.WithValue(ctx, muxStreamKey{}, (*muxStream)(nil))
	}
	s := &muxStream{conn: stream, session: session}
	s.timer = time.AfterFunc(muxHandshakeTimeout, s.expire)
	return context.WithValue(ctx, muxStreamKey{}, s)
}

// muxStreamStarted is called when a connection reaches the handler: for a
// sing-mux stream, its request has been read, so the handshake timer stops.
// The returned function frees the stream's slot in its session and must be
// called when the handler is done with the stream.
func muxStreamStarted(ctx context.Context) (done func()) {
	s, _ := ctx.Value(muxStreamKey{}).(*muxStream)
	if s == nil || !s.started.CompareAndSwap(false, true) {
		// not a mux stream, already started by an outer handler, or expired
		return func() {}
	}
	s.timer.Stop()
	return s.release
}
