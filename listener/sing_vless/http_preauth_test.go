package sing_vless

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/vless"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
)

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type echoTunnel struct{}

func (echoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func (echoTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}
func (echoTunnel) NatTable() C.NatTable                                     { return nil }

// startHTTPListener starts a VLESS listener on 127.0.0.1 and returns its
// address. Call shortHandshakeTimeout before it.
func startHTTPListener(t *testing.T, config LC.VlessServer, withTLS bool) string {
	t.Helper()
	config.Listen = "127.0.0.1:0"
	config.Users = []LC.VlessUser{{Username: "test", UUID: testUUID}}
	if withTLS {
		cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			t.Fatal(err)
		}
		config.Certificate, config.PrivateKey = cert, key
	} else {
		config.AllowInsecure = true
	}
	l, err := New(config, &net.ListenConfig{}, echoTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.AddrList()[0].String()
}

// expectEOFWithin asserts the server closes client within limit. The server
// may write first (h2 settings), so the reads go until the conn ends.
func expectEOFWithin(t *testing.T, client net.Conn, limit time.Duration) {
	t.Helper()
	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(limit))
	_, err := io.Copy(io.Discard, client)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept a conn with no request open for %v", limit)
	}
	t.Logf("closed after %v (err: %v)", time.Since(start), err)
}

// TestVlessHTTPSilentClientClosed: a client that connects to a grpc or xhttp
// VLESS listener and sends no request is closed within the handshake timeout.
// The server waits for the h2c preface with no deadline of its own: on plain
// conns, and on TLS conns that did not negotiate h2.
func TestVlessHTTPSilentClientClosed(t *testing.T) {
	grpc := LC.VlessServer{GrpcServiceName: "GunService"}
	xh := LC.VlessServer{XHTTPConfig: LC.XHTTPConfig{Path: "/x"}}
	cases := []struct {
		name    string
		config  LC.VlessServer
		withTLS bool
		alpn    []string
		send    string
	}{
		{name: "grpc/plain", config: grpc},
		{name: "grpc/plain/h2c-preface-only", config: grpc, send: h2Preface + "\x00\x00\x00\x04\x00\x00\x00\x00\x00"},
		{name: "grpc/tls/no-alpn", config: grpc, withTLS: true},
		{name: "grpc/tls/h2-preface-only", config: grpc, withTLS: true, alpn: []string{"h2"}, send: h2Preface + "\x00\x00\x00\x04\x00\x00\x00\x00\x00"},
		{name: "xhttp/plain", config: xh},
		{name: "xhttp/plain/partial-preface", config: xh, send: "PRI * HTTP"},
		{name: "xhttp/tls/no-alpn", config: xh, withTLS: true},
		{name: "xhttp/tls/http1.1", config: xh, withTLS: true, alpn: []string{"http/1.1"}},
	}
	shortHandshakeTimeout(t, 300*time.Millisecond)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startHTTPListener(t, tc.config, tc.withTLS)
			client, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if tc.withTLS {
				tlsConn := tls.Client(client, &tls.Config{InsecureSkipVerify: true, NextProtos: tc.alpn})
				if err := tlsConn.Handshake(); err != nil {
					t.Fatal(err)
				}
				client = tlsConn
			}
			if tc.send != "" {
				if _, err := client.Write([]byte(tc.send)); err != nil {
					t.Fatal(err)
				}
			}
			expectEOFWithin(t, client, 4*time.Second)
		})
	}
}

// exchangeAfterIdle sends the VLESS request header on conn, idles past the
// handshake timeout, then expects its data echoed back.
func exchangeAfterIdle(t *testing.T, conn net.Conn, idle time.Duration) {
	t.Helper()
	if _, err := conn.Write(vlessRequestHeader(t)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(idle)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 2+5)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("idle session was cut: %v", err)
	}
	if !bytes.Equal(resp, []byte{vless.Version, 0, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("unexpected response %q", resp)
	}
}

// TestVlessGrpcIdleSessionKept: once a gRPC stream has reached the handler,
// neither the stream idle past the handshake timeout nor the h2 conn idle
// between streams is cut.
func TestVlessGrpcIdleSessionKept(t *testing.T) {
	for _, withTLS := range []bool{false, true} {
		name := "plain"
		if withTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			timeout := 300 * time.Millisecond
			shortHandshakeTimeout(t, timeout)
			addr := startHTTPListener(t, LC.VlessServer{GrpcServiceName: "GunService"}, withTLS)
			var tlsConfig *vmess.TLSConfig
			if withTLS {
				tlsConfig = &vmess.TLSConfig{Host: "example.com", SkipCertVerify: true, NextProtos: []string{"h2"}}
			}
			dials := 0
			transport := gun.NewTransport(func(ctx context.Context, network, _ string) (net.Conn, error) {
				dials++
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}, tlsConfig, &gun.Config{ServiceName: "GunService", Host: "example.com"})
			defer transport.Close()

			conn, err := transport.Dial()
			if err != nil {
				t.Fatal(err)
			}
			exchangeAfterIdle(t, conn, 3*timeout)
			_ = conn.Close()

			// the h2 conn idles between streams, then carries a new one
			time.Sleep(3 * timeout)
			conn, err = transport.Dial()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			exchangeAfterIdle(t, conn, 3*timeout)
			if dials != 1 {
				t.Fatalf("h2 conn was not reused: %d dials", dials)
			}
		})
	}
}

// TestVlessXHTTPIdleSessionKept: an xhttp session (long download GET, stream
// upload, packet-up over HTTP/1.1) idle past the handshake timeout is not cut.
func TestVlessXHTTPIdleSessionKept(t *testing.T) {
	cases := []struct {
		mode string
		alpn []string
	}{
		{mode: "stream-one"},
		{mode: "stream-up"},
		{mode: "packet-up", alpn: []string{"http/1.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			timeout := 300 * time.Millisecond
			shortHandshakeTimeout(t, timeout)
			addr := startHTTPListener(t, LC.VlessServer{XHTTPConfig: LC.XHTTPConfig{Path: "/x", Mode: tc.mode}}, false)
			makeTransport := func() http.RoundTripper {
				return xhttp.NewTransport(
					func(ctx context.Context) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "tcp", addr)
					},
					func(ctx context.Context, raw net.Conn, isH2 bool) (net.Conn, error) { return raw, nil },
					nil, tc.alpn, 0)
			}
			client, err := xhttp.NewClient(&xhttp.Config{Host: "example.com", Path: "/x", Mode: tc.mode}, makeTransport, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			conn, err := client.Dial(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			exchangeAfterIdle(t, conn, 3*timeout)
		})
	}
}
