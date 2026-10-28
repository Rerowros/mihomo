package trojan

import (
	"net"
	"time"
)

// handshakeTimeout bounds how long a client may take, from the moment its
// connection reaches the Trojan layer, to send the request header (password
// key, command, address and the CRLFs).
// Without it a client that connects and sends nothing, or trickles bytes,
// holds a goroutine and its buffers forever before it is authenticated.
//
// Xray-core uses policy timeouts.handshake (4s by default) for the same window.
// The value here is more generous, so that slow mobile links (and the first
// read of a lazy TLS handshake on the tls listener) are not cut. The deadline
// is cleared once the user is authenticated, so an idle session after that is
// never affected. A variable only so that tests can shorten it.
var handshakeTimeout = 15 * time.Second

// maxMuxStreams caps the streams one Trojan mux (smux) session may have open
// at once; a stream beyond it is closed as soon as it is accepted. Every
// stream costs a goroutine, so without a cap one authenticated client could
// open streams until the process runs out of memory. 1024 is far above what
// one client multiplexes (a phone with a few hundred connections). A variable
// only so that tests can lower it.
var maxMuxStreams = 1024

// setHandshakeDeadline arms the pre-authentication read deadline. Every conn
// that reaches the Trojan layer supports it: TCP, TLS, REALITY, ShadowTLS,
// ResTLS, JLS, and ws, gun and xhttp (wrapped in N.NewDeadlineConn).
func setHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
}

// clearHandshakeDeadline lifts the deadline set by setHandshakeDeadline.
func clearHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Time{})
}
