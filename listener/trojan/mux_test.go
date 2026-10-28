package trojan

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/trojan"

	"github.com/metacubex/smux"
)

// openTrojanMux authenticates with the mux command and returns the client
// side of the smux session.
func openTrojanMux(t *testing.T, l *Listener) *smux.Session {
	t.Helper()
	client := serveTrojanOnce(t, l)
	if _, err := client.Write(trojanRequestHeader(t, trojan.CommandMux)); err != nil {
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

// expectStreamClosedWithin asserts the server closes stream within limit.
func expectStreamClosedWithin(t *testing.T, stream *smux.Stream, limit time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(limit))
	_, err := stream.Read(make([]byte, 1))
	if isTimeout(err) {
		t.Fatalf("server kept the stream open for %v", limit)
	}
	if err == nil {
		t.Fatal("server sent data on a stream without a request")
	}
	return time.Since(start)
}

// A mux stream that never sends its command and target used to hold its
// goroutine for the life of the session.
func TestTrojanMuxStreamHandshakeTimeout(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	session := openTrojanMux(t, newTestTrojanListener(t, 0))
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	expectStreamClosedWithin(t, stream, 3*time.Second)
}

// One session may not have more than maxMuxStreams streams being served; a
// stream beyond it is closed at once.
func TestTrojanMuxStreamCap(t *testing.T) {
	shortHandshakeTimeout(t, 2*time.Second)
	old := maxMuxStreams
	maxMuxStreams = 2
	t.Cleanup(func() { maxMuxStreams = old })

	session := openTrojanMux(t, newTestTrojanListener(t, 0))
	var streams []*smux.Stream
	for i := 0; i < 3; i++ {
		stream, err := session.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
	}
	if elapsed := expectStreamClosedWithin(t, streams[2], time.Second); elapsed > 500*time.Millisecond {
		t.Fatalf("stream over the cap closed after %v, want at once", elapsed)
	}
	// the streams within the cap are still open
	for i := 0; i < 2; i++ {
		_ = streams[i].SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := streams[i].Read(make([]byte, 1)); !isTimeout(err) {
			t.Fatalf("stream %d within the cap: %v", i, err)
		}
	}
}
