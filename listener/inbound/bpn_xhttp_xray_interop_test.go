package inbound_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/stretchr/testify/require"
)

// TestBPNXHTTPPacketUpXrayInterop runs mihomo VLESS + XHTTP packet-up against
// a local Xray-core server (TLS, no CDN), with POST uplink and with GET uplink
// that carries the data in X-Payload-N headers. Every case moves a large
// payload each way and checks its sha256. With the one-way delay proxy it
// measures upload throughput with sequential uploads (1 request in flight,
// upstream mihomo) and parallel uploads (BadVPN patch P5). No internet access
// is needed.
//
//	XRAY_BINARY=/path/to/xray go test ./listener/inbound -run BPNXHTTPPacketUpXrayInterop -v
//
// Every measurement logs a "THROUGHPUT" line. See BADVPN.md (P5).
func TestBPNXHTTPPacketUpXrayInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	xrayVersion := strings.Fields(string(versionOutput))[1]
	t.Logf("Xray executable: %s (%s)", xrayBinary, xrayVersion)

	target := bpnXHTTPStartTarget(t)

	uplinks := []struct {
		name  string
		extra map[string]any // Xray xhttpSettings
		opts  func(*outbound.XHTTPOptions)
	}{
		{
			name:  "post",
			extra: map[string]any{},
			opts:  func(*outbound.XHTTPOptions) {},
		},
		{
			name: "get-header",
			extra: map[string]any{
				"uplinkHTTPMethod":    "GET",
				"uplinkDataPlacement": "header",
				"uplinkDataKey":       "X-Payload",
				"uplinkChunkSize":     "8192-12288",
				// 64 KB of payload is ~87 KB of base64 headers; the Xray
				// default is 8192
				"serverMaxHeaderBytes": 131072,
			},
			opts: func(o *outbound.XHTTPOptions) {
				o.UplinkHTTPMethod = "GET"
				o.UplinkDataPlacement = "header"
				o.UplinkDataKey = "X-Payload"
				o.UplinkChunkSize = "8192-12288"
			},
		},
	}
	alpns := []struct {
		name string
		alpn []string
	}{
		{name: "h2"},
		{name: "h1", alpn: []string{"http/1.1"}},
	}

	for _, uplink := range uplinks {
		t.Run(uplink.name, func(t *testing.T) {
			xrayPort := vmessInteropReserveTCPPort(t)
			config := bpnXHTTPXrayConfig(t, xrayPort.Port(), uplink.extra)
			bpnMatrixStartXray(t, xrayBinary, config, xrayPort)
			xrayAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(xrayPort.Port()))

			for _, alpn := range alpns {
				t.Run(alpn.name, func(t *testing.T) {
					newOutbound := func(t *testing.T, addr string) *outbound.Vless {
						host, port, err := net.SplitHostPort(addr)
						require.NoError(t, err)
						var portNum int
						_, err = fmt.Sscan(port, &portNum)
						require.NoError(t, err)
						opts := outbound.XHTTPOptions{
							Path:                 "/bpn-xhttp",
							Host:                 "example.com",
							Mode:                 "packet-up",
							ScMaxEachPostBytes:   "32768-65536",
							ScMinPostsIntervalMs: "30",
						}
						uplink.opts(&opts)
						out, err := outbound.NewVless(outbound.VlessOption{
							Name:           "bpn_xhttp_interop",
							Server:         host,
							Port:           portNum,
							UUID:           bpnMatrixUUID,
							TLS:            true,
							ServerName:     "example.com",
							SkipCertVerify: true,
							Network:        "xhttp",
							ALPN:           alpn.alpn,
							XHTTPOpts:      opts,
						})
						require.NoError(t, err)
						t.Cleanup(func() { _ = out.Close() })
						return out
					}

					t.Run("big-payloads", func(t *testing.T) {
						out := newOutbound(t, xrayAddr)
						conn := bpnXHTTPDial(t, out, target)
						defer conn.Close()
						up, err := bpnXHTTPUpload(conn, 16*1024*1024)
						require.NoError(t, err)
						down, err := bpnXHTTPDownload(conn, 16*1024*1024)
						require.NoError(t, err)
						t.Logf("THROUGHPUT xray=%s %s/%s no-delay n=%d: up 16 MiB %.1f Mbit/s, down 16 MiB %.1f Mbit/s",
							xrayVersion, uplink.name, alpn.name, xhttp.PacketUpMaxInFlight, up, down)
					})

					// 75 ms each way = 150 ms round trip, like a CDN hop
					proxyAddr := bpnXHTTPStartDelayProxy(t, xrayAddr, 75*time.Millisecond)
					var rates []float64
					for _, n := range []int{1, xhttp.PacketUpMaxInFlight} {
						t.Run(fmt.Sprintf("rtt150/n=%d", n), func(t *testing.T) {
							restore := xhttp.SetPacketUpMaxInFlightForTest(n)
							defer restore()
							out := newOutbound(t, proxyAddr)
							conn := bpnXHTTPDial(t, out, target)
							defer conn.Close()
							const size = 2 * 1024 * 1024
							up, err := bpnXHTTPUpload(conn, size)
							require.NoError(t, err)
							down, err := bpnXHTTPDownload(conn, 4*1024*1024)
							require.NoError(t, err)
							rates = append(rates, up)
							t.Logf("THROUGHPUT xray=%s %s/%s rtt=150ms n=%d: up 2 MiB %.2f Mbit/s, down 4 MiB %.1f Mbit/s",
								xrayVersion, uplink.name, alpn.name, n, up, down)
						})
					}
					if len(rates) == 2 {
						t.Logf("THROUGHPUT xray=%s %s/%s rtt=150ms: parallel/sequential upload = %.1fx",
							xrayVersion, uplink.name, alpn.name, rates[1]/rates[0])
						// h1 opens a TLS connection per request in flight (2-3
						// round trips each), so its gain on 2 MiB is smaller
						minGain := 2.5
						if alpn.name == "h1" {
							minGain = 1.5
						}
						require.Greater(t, rates[1], minGain*rates[0], "parallel upload must be much faster")
					}
				})
			}
		})
	}
}

func bpnXHTTPDial(t *testing.T, out *outbound.Vless, target string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, vmessInteropMetadata(t, target))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Minute)))
	return conn
}

// bpnXHTTPUpload sends n random bytes; the target answers with their sha256.
// It returns the upload rate in Mbit/s.
func bpnXHTTPUpload(conn net.Conn, n int) (float64, error) {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		return 0, err
	}
	var header [9]byte
	header[0] = 'U'
	binary.BigEndian.PutUint64(header[1:], uint64(n))
	start := time.Now()
	if _, err := conn.Write(header[:]); err != nil {
		return 0, err
	}
	if _, err := conn.Write(data); err != nil {
		return 0, fmt.Errorf("upload: %w", err)
	}
	var sum [sha256.Size]byte
	if _, err := io.ReadFull(conn, sum[:]); err != nil {
		return 0, fmt.Errorf("upload ack: %w", err)
	}
	elapsed := time.Since(start)
	if sum != sha256.Sum256(data) {
		return 0, errors.New("upload: sha256 mismatch")
	}
	return float64(n) * 8 / elapsed.Seconds() / 1e6, nil
}

// bpnXHTTPDownload asks the target for n random bytes followed by their
// sha256. It returns the download rate in Mbit/s.
func bpnXHTTPDownload(conn net.Conn, n int) (float64, error) {
	var header [9]byte
	header[0] = 'D'
	binary.BigEndian.PutUint64(header[1:], uint64(n))
	start := time.Now()
	if _, err := conn.Write(header[:]); err != nil {
		return 0, err
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, conn, int64(n)); err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	elapsed := time.Since(start)
	var sum [sha256.Size]byte
	if _, err := io.ReadFull(conn, sum[:]); err != nil {
		return 0, fmt.Errorf("download sha256: %w", err)
	}
	if string(sum[:]) != string(hash.Sum(nil)) {
		return 0, errors.New("download: sha256 mismatch")
	}
	return float64(n) * 8 / elapsed.Seconds() / 1e6, nil
}

// bpnXHTTPStartTarget serves 'U' (read n bytes, answer sha256) and 'D' (send
// n random bytes, then their sha256) commands.
func bpnXHTTPStartTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					var header [9]byte
					if _, err := io.ReadFull(conn, header[:]); err != nil {
						return
					}
					n := int64(binary.BigEndian.Uint64(header[1:]))
					hash := sha256.New()
					switch header[0] {
					case 'U':
						if _, err := io.CopyN(hash, conn, n); err != nil {
							return
						}
					case 'D':
						if _, err := io.CopyN(io.MultiWriter(conn, hash), rand.Reader, n); err != nil {
							return
						}
					default:
						return
					}
					if _, err := conn.Write(hash.Sum(nil)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// bpnXHTTPStartDelayProxy forwards TCP to upstream and delays every chunk by
// oneWay in each direction, keeping the order (no bandwidth limit).
func bpnXHTTPStartDelayProxy(t *testing.T, upstream string, oneWay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				server, err := net.Dial("tcp", upstream)
				if err != nil {
					_ = client.Close()
					return
				}
				done := make(chan struct{}, 2)
				go func() { bpnXHTTPDelayPipe(server, client, oneWay); done <- struct{}{} }()
				go func() { bpnXHTTPDelayPipe(client, server, oneWay); done <- struct{}{} }()
				<-done
				_ = client.Close()
				_ = server.Close()
				<-done
			}()
		}
	}()
	return ln.Addr().String()
}

func bpnXHTTPDelayPipe(dst, src net.Conn, delay time.Duration) {
	type chunk struct {
		data []byte
		at   time.Time
	}
	chunks := make(chan chunk, 8192)
	go func() {
		defer close(chunks)
		for {
			buf := make([]byte, 32*1024)
			n, err := src.Read(buf)
			if n > 0 {
				chunks <- chunk{data: buf[:n], at: time.Now().Add(delay)}
			}
			if err != nil {
				return
			}
		}
	}()
	for c := range chunks {
		if wait := time.Until(c.at); wait > 0 {
			time.Sleep(wait)
		}
		if _, err := dst.Write(c.data); err != nil {
			break
		}
	}
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	for range chunks { // unblock the reader
	}
}

func bpnXHTTPXrayConfig(t *testing.T, port int, extra map[string]any) []byte {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, []byte(tlsCertificate), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte(tlsPrivateKey), 0o600))

	xhttpSettings := map[string]any{
		"path":               "/bpn-xhttp",
		"host":               "example.com",
		"mode":               "packet-up",
		"scMaxEachPostBytes": 65536,
		"scMaxBufferedPosts": 30,
	}
	for k, v := range extra {
		xhttpSettings[k] = v
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": bpnMatrixUUID}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network":  "xhttp",
				"security": "tls",
				"tlsSettings": map[string]any{
					"alpn":         []string{"h2", "http/1.1"},
					"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}},
				},
				"xhttpSettings": xhttpSettings,
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{
				// Newer Xray blocks private destinations by default; the
				// target is loopback-only.
				"finalRules": []any{map[string]any{"action": "allow"}},
			},
		}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	return data
}
