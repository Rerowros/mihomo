package anytls

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// shortHandshakeTimeout shortens handshakeTimeout for one test.
func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := handshakeTimeout
	handshakeTimeout = d
	t.Cleanup(func() { handshakeTimeout = old })
}

// serveAnyTLSOnce accepts one TCP connection and serves it with l.HandleConn.
func serveAnyTLSOnce(t *testing.T, l *Listener) net.Conn {
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

func TestAnyTLSHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveAnyTLSOnce(t, &Listener{userMap: map[[32]byte]string{}})
	expectClosedWithin(t, client, 3*time.Second)
}
