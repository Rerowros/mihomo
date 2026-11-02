package trojan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"
)

const testPassword = "trojan-test-password"

// shortHandshakeTimeout shortens handshakeTimeout for one test.
func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := handshakeTimeout
	handshakeTimeout = d
	t.Cleanup(func() { handshakeTimeout = old })
}

// echoTunnel idles, then echoes five bytes of every TCP conn it is handed.
type echoTunnel struct {
	idle time.Duration
}

func (t echoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	time.Sleep(t.idle)
	b := make([]byte, 5)
	if _, err := io.ReadFull(conn, b); err != nil {
		return
	}
	_, _ = conn.Write(b)
}

func (t echoTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}
func (t echoTunnel) NatTable() C.NatTable                                     { return nil }

func newTestTrojanListener(t *testing.T, idle time.Duration) *Listener {
	t.Helper()
	h, err := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: echoTunnel{idle: idle}, Type: C.TROJAN})
	if err != nil {
		t.Fatal(err)
	}
	return &Listener{
		keys:    map[[trojan.KeyLength]byte]string{trojan.Key(testPassword): "test"},
		handler: h,
	}
}

// serveTrojanOnce accepts one TCP connection and serves it with l.HandleConn.
func serveTrojanOnce(t *testing.T, l *Listener) net.Conn {
	t.Helper()
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
		l.HandleConn(c, nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func trojanRequestHeader(t *testing.T, command trojan.Command) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := trojan.WriteHeader(&b, trojan.Key(testPassword), command, socks5.ParseAddr("1.2.3.4:80")); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// expectClosedWithin asserts the server closes client within limit.
func expectClosedWithin(t *testing.T, client net.Conn, limit time.Duration) {
	t.Helper()
	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(limit))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept the conn open for %v", limit)
	}
	if err == nil {
		t.Fatal("server sent data to a client that did not finish its header")
	}
	t.Logf("closed after %v: %v", time.Since(start), err)
}

func TestTrojanHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveTrojanOnce(t, newTestTrojanListener(t, 0))
	expectClosedWithin(t, client, 3*time.Second)
}

func TestTrojanHandshakeTimeoutTricklingClient(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	client := serveTrojanOnce(t, newTestTrojanListener(t, 0))
	header := trojanRequestHeader(t, trojan.CommandTCP)
	go func() {
		// one byte every 20ms: each read makes progress, the header never ends in time
		for _, c := range header[:len(header)-1] {
			if _, err := client.Write([]byte{c}); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	expectClosedWithin(t, client, 3*time.Second)
}

func TestTrojanHandshakeDeadlineClearedAfterAuth(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	client := serveTrojanOnce(t, newTestTrojanListener(t, 4*timeout))
	if _, err := client.Write(trojanRequestHeader(t, trojan.CommandTCP)); err != nil {
		t.Fatal(err)
	}
	// idle well past the handshake timeout on both sides
	time.Sleep(4 * timeout)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 5)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}
