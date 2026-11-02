package snell

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/snell"
)

const testPsk = "snell-test-psk"

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

func serveSnellOnce(t *testing.T, tunnel C.Tunnel) net.Conn {
	t.Helper()
	l := &Listener{config: LC.SnellServer{Psk: testPsk, Version: snell.Version4}}
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
		l.HandleConn(c, tunnel)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSnellHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveSnellOnce(t, echoTunnel{})
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("server kept the unauthenticated conn open")
	}
	if err == nil {
		t.Fatal("server sent data to an unauthenticated client")
	}
}

func TestSnellHandshakeDeadlineClearedAfterRequest(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	raw := serveSnellOnce(t, echoTunnel{idle: 4 * timeout})
	client := snell.StreamConn(raw, []byte(testPsk), snell.Version4)
	if err := snell.WriteHeader(client, "1.2.3.4", 80, snell.Version4); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * timeout)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := client.ReadReply(); err != nil {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}
