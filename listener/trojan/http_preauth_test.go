package trojan

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/trojan"
	"github.com/metacubex/mihomo/transport/vmess"
)

// startGrpcListener starts a Trojan grpc listener on 127.0.0.1 and returns
// its address. Call shortHandshakeTimeout before it.
func startGrpcListener(t *testing.T, withTLS bool, idle time.Duration) string {
	t.Helper()
	config := LC.TrojanServer{
		Listen:          "127.0.0.1:0",
		Users:           []LC.TrojanUser{{Username: "test", Password: testPassword}},
		GrpcServiceName: "GunService",
	}
	if withTLS {
		cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			t.Fatal(err)
		}
		config.Certificate, config.PrivateKey = cert, key
	} else {
		config.AllowInsecure = true
	}
	l, err := New(config, &net.ListenConfig{}, echoTunnel{idle: idle})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.AddrList()[0].String()
}

// TestTrojanGrpcSilentClientClosed: a client that connects to a grpc Trojan
// listener and sends no request is closed within the handshake timeout. The
// server waits for the h2c preface with no deadline of its own: on plain
// conns, and on TLS conns that did not negotiate h2.
func TestTrojanGrpcSilentClientClosed(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	for _, withTLS := range []bool{false, true} {
		name := "plain"
		if withTLS {
			name = "tls/no-alpn"
		}
		t.Run(name, func(t *testing.T) {
			addr := startGrpcListener(t, withTLS, 0)
			client, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if withTLS {
				tlsConn := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
				if err := tlsConn.Handshake(); err != nil {
					t.Fatal(err)
				}
				client = tlsConn
			}
			start := time.Now()
			_ = client.SetReadDeadline(time.Now().Add(4 * time.Second))
			_, err = io.Copy(io.Discard, client)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("server kept a conn with no request open for 4s")
			}
			t.Logf("closed after %v (err: %v)", time.Since(start), err)
		})
	}
}

// TestTrojanGrpcIdleSessionKept: a gRPC stream that reached the handler and
// idles past the handshake timeout is not cut.
func TestTrojanGrpcIdleSessionKept(t *testing.T) {
	timeout := 300 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	addr := startGrpcListener(t, false, 3*timeout)
	transport := gun.NewTransport(func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}, (*vmess.TLSConfig)(nil), &gun.Config{ServiceName: "GunService", Host: "example.com"})
	defer transport.Close()
	conn, err := transport.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(trojanRequestHeader(t, trojan.CommandTCP)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * timeout)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 5)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("idle session was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}
