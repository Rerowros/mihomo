package http

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
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

func serveHTTPOnce(t *testing.T, tunnel C.Tunnel) net.Conn {
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
		HandleConn(c, tunnel, authStore.Nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
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
		t.Fatalf("server kept the conn open for %v", limit)
	}
	if err == nil {
		t.Fatal("server answered a request it never fully received")
	}
	t.Logf("closed after %v: %v", time.Since(start), err)
}

const connectRequest = "CONNECT 1.2.3.4:80 HTTP/1.1\r\nHost: 1.2.3.4:80\r\n\r\n"

func TestHTTPHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveHTTPOnce(t, echoTunnel{})
	expectClosedWithin(t, client, 3*time.Second)
}

func TestHTTPHandshakeTimeoutTricklingClient(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	client := serveHTTPOnce(t, echoTunnel{})
	go func() {
		for _, c := range []byte(connectRequest[:len(connectRequest)-1]) {
			if _, err := client.Write([]byte{c}); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	expectClosedWithin(t, client, 3*time.Second)
}

func TestHTTPHandshakeDeadlineClearedAfterConnect(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	client := serveHTTPOnce(t, echoTunnel{idle: 4 * timeout})
	if _, err := client.Write([]byte(connectRequest)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(client)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %q %v", status, err)
	}
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// idle well past the handshake timeout on both sides
	time.Sleep(4 * timeout)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(br, resp); err != nil {
		t.Fatalf("established tunnel was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}
