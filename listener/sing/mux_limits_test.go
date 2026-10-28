package sing

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	mux "github.com/metacubex/sing-mux"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/smux"
)

// closingTunnel closes every TCP conn it is handed.
type closingTunnel struct{}

func (closingTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata)        { _ = conn.Close() }
func (closingTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}
func (closingTunnel) NatTable() C.NatTable                                     { return nil }

func setMuxLimits(t *testing.T, maxStreams int32, timeout time.Duration) {
	oldMax, oldTimeout := muxMaxStreams, muxHandshakeTimeout
	muxMaxStreams, muxHandshakeTimeout = maxStreams, timeout
	t.Cleanup(func() { muxMaxStreams, muxHandshakeTimeout = oldMax, oldTimeout })
}

// openSingMux hands one end of a TCP pair to the handler as a sing-mux
// connection and returns the client side smux session.
func openSingMux(t *testing.T) *smux.Session {
	t.Helper()
	h, err := NewListenerHandler(ListenerConfig{Tunnel: closingTunnel{}, Type: C.VLESS})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = h.NewConnection(context.Background(), c, M.Metadata{
			Source:      M.SocksaddrFromNet(c.RemoteAddr()),
			Destination: mux.Destination,
		})
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// sing-mux request: version 0, smux
	if _, err := client.Write([]byte{mux.Version0, mux.ProtocolSmux}); err != nil {
		t.Fatal(err)
	}
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := smux.Client(client, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// streamClosedWithin reports whether the server closed stream within limit.
func streamClosedWithin(stream *smux.Stream, limit time.Duration) bool {
	_ = stream.SetReadDeadline(time.Now().Add(limit))
	_, err := stream.Read(make([]byte, 1))
	return err != nil && !isTimeout(err)
}

func openStream(t *testing.T, session *smux.Session) *smux.Stream {
	t.Helper()
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

// A stream that never sends its request used to hold its goroutine for the
// life of the session.
func TestSingMuxStreamHandshakeTimeout(t *testing.T) {
	setMuxLimits(t, 1024, 300*time.Millisecond)
	session := openSingMux(t)
	stream := openStream(t, session)
	if !streamClosedWithin(stream, 3*time.Second) {
		t.Fatal("a stream without a request was kept open")
	}
}

// A session may not have more than muxMaxStreams streams; a stream beyond it
// is closed at once, and a finished stream frees its slot.
func TestSingMuxStreamCap(t *testing.T) {
	setMuxLimits(t, 2, 5*time.Second)
	session := openSingMux(t)

	// a stream with a request: the tunnel closes it, its slot is freed
	done := openStream(t, session)
	request := []byte{0, 0, 1, 127, 0, 0, 1, 0, 80} // TCP, 127.0.0.1:80
	if _, err := done.Write(request); err != nil {
		t.Fatal(err)
	}
	if !streamClosedWithin(done, 3*time.Second) {
		t.Fatal("the relayed stream was not closed by the tunnel")
	}
	time.Sleep(100 * time.Millisecond) // the handler returns right after the close

	// two idle streams fit, the third is over the cap
	first, second, third := openStream(t, session), openStream(t, session), openStream(t, session)
	if !streamClosedWithin(third, time.Second) {
		t.Fatal("a stream over the cap was kept open")
	}
	for i, stream := range []*smux.Stream{first, second} {
		if streamClosedWithin(stream, 100*time.Millisecond) {
			t.Fatalf("stream %d within the cap was closed", i)
		}
	}
}
