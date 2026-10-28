package shadowsocks

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
)

const (
	testCipher   = "aes-128-gcm"
	testPassword = "shadowsocks-test-password"
)

func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := authStore.HandshakeTimeout
	authStore.HandshakeTimeout = d
	t.Cleanup(func() { authStore.HandshakeTimeout = old })
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

func dialTestListener(t *testing.T, tunnel C.Tunnel) net.Conn {
	t.Helper()
	l, err := New(LC.ShadowsocksServer{
		Enable:   true,
		Listen:   "127.0.0.1:0",
		Password: testPassword,
		Cipher:   testCipher,
	}, inbound.ListenConfig{}, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	client, err := net.Dial("tcp", l.AddrList()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func expectClosedWithin(t *testing.T, client net.Conn, limit time.Duration) {
	t.Helper()
	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(limit))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept the unauthenticated conn open for %v", limit)
	}
	if err == nil {
		t.Fatal("server sent data to an unauthenticated client")
	}
	t.Logf("closed after %v: %v", time.Since(start), err)
}

func TestEmbeddedShadowsocksHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := dialTestListener(t, echoTunnel{})
	expectClosedWithin(t, client, 3*time.Second)
}

func TestEmbeddedShadowsocksHandshakeTimeoutPartialSalt(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	client := dialTestListener(t, echoTunnel{})
	// half a salt, then nothing
	if _, err := client.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	expectClosedWithin(t, client, 3*time.Second)
}

func TestEmbeddedShadowsocksHandshakeDeadlineClearedAfterAuth(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	raw := dialTestListener(t, echoTunnel{idle: 4 * timeout})
	cipher, err := core.PickCipher(testCipher, nil, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	client := cipher.StreamConn(raw)
	if _, err := client.Write(socks5.ParseAddr("1.2.3.4:80")); err != nil {
		t.Fatal(err)
	}
	// idle well past the handshake timeout on both sides
	time.Sleep(4 * timeout)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 5)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}
