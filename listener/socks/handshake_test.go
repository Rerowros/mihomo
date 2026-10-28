package socks

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/transport/socks5"
)

// shortHandshakeTimeout shortens authStore.HandshakeTimeout for one test.
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

func serveSocksOnce(t *testing.T, tunnel C.Tunnel) net.Conn {
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
		handleSocks(c, tunnel, authStore.Nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// expectClosedWithin asserts the server closes client within limit (a
// greeting reply may come first).
func expectClosedWithin(t *testing.T, client net.Conn, limit time.Duration) {
	t.Helper()
	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(limit))
	_, err := io.Copy(io.Discard, client)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept the conn open for %v", limit)
	}
	t.Logf("closed after %v: %v", time.Since(start), err)
}

func TestSocksHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveSocksOnce(t, echoTunnel{})
	expectClosedWithin(t, client, 3*time.Second)
}

func TestSocks5HandshakeTimeoutAfterGreeting(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	client := serveSocksOnce(t, echoTunnel{})
	// the greeting, then never the request
	if _, err := client.Write([]byte{socks5.Version, 1, 0}); err != nil {
		t.Fatal(err)
	}
	expectClosedWithin(t, client, 3*time.Second)
}

func TestSocks4HandshakeTimeoutPartialRequest(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	client := serveSocksOnce(t, echoTunnel{})
	// version, command, port and IP, but never the NUL-terminated user id
	if _, err := client.Write([]byte{4, 1, 0, 80, 1, 2, 3, 4, 'u'}); err != nil {
		t.Fatal(err)
	}
	expectClosedWithin(t, client, 3*time.Second)
}

func TestSocks5HandshakeDeadlineClearedAfterRequest(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	client := serveSocksOnce(t, echoTunnel{idle: 4 * timeout})
	req := append([]byte{socks5.Version, 1, 0, socks5.Version, socks5.CmdConnect, 0}, socks5.ParseAddr("1.2.3.4:80")...)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	// method selection (2) and the reply (10 for an IPv4 bind address)
	if _, err := io.ReadFull(client, make([]byte, 2+10)); err != nil {
		t.Fatal(err)
	}
	// idle well past the handshake timeout on both sides
	time.Sleep(4 * timeout)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("established connection was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}
