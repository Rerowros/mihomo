package inbound_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

const (
	bpnMatrixUUID    = "5f0c3a1e-8d7b-4c52-9a3e-2b6f1d4e7a90"
	bpnMatrixShortID = "0123456789abcdef"
)

// TestBPNRealityXrayMatrix connects mihomo VLESS+REALITY (tcp, no flow) to a
// local Xray-core REALITY server, for each client fingerprint, against local
// TLS targets: Go with X25519MLKEM768 (Go default), Go with only X25519 and
// with X25519+P-256 (like real REALITY targets without ML-KEM), and, if
// OPENSSL_BINARY is set, "openssl s_server" with the OpenSSL 3.0 default
// groups (no ML-KEM). No internet access is needed.
//
//	XRAY_BINARY=/path/to/xray [OPENSSL_BINARY=/path/to/openssl] go test ./listener/inbound -run BPNRealityXrayMatrix -v
//
// Every case logs a "MATRIX" line. See BADVPN.md (P4) for the results.
// Required: default (ML-KEM stripped) chrome/firefox/safari/empty on Xray
// < 26.9.8 with every target. Informational: everything on Xray >= 26.9.8
// (XTLS/REALITY 8cdf7bf rejects ClientHellos without X25519MLKEM768), edge
// (Edge 85, no ML-KEM) and support-x25519mlkem768: true.
func TestBPNRealityXrayMatrix(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	xrayVersion := strings.Fields(string(versionOutput))[1]
	t.Logf("Xray executable: %s (%s)", xrayBinary, xrayVersion)
	xrayRequiresMLKEM := bpnMatrixVersionAtLeast(t, xrayVersion, 26, 9, 8)

	echoAddr := startVMessInteropEcho(t)

	goTarget := func(curves ...tls.CurveID) func(t *testing.T) string {
		return func(t *testing.T) string {
			return startTLSMirrorInteropCarrierTLS(t, func(c *tls.Config) { c.CurvePreferences = curves }).addr
		}
	}
	targets := []struct {
		name  string
		start func(t *testing.T) string
	}{
		{name: "target-mlkem", start: goTarget()},
		{name: "target-x25519", start: goTarget(tls.X25519)},
		{name: "target-x25519-p256", start: goTarget(tls.X25519, tls.CurveP256)},
	}
	if opensslBinary := os.Getenv("OPENSSL_BINARY"); opensslBinary != "" {
		targets = append(targets, struct {
			name  string
			start func(t *testing.T) string
		}{name: "target-openssl-no-mlkem", start: func(t *testing.T) string {
			return bpnMatrixStartOpenSSLTarget(t, opensslBinary, "X25519:P-256:X448:P-521:P-384")
		}})
	}
	testCases := []struct {
		fingerprint   string
		mlkem         bool
		informational bool
	}{
		{fingerprint: "chrome"},
		{fingerprint: "firefox"},
		{fingerprint: "safari"},
		{fingerprint: ""},
		{fingerprint: "edge", informational: true},
		{fingerprint: "chrome", mlkem: true, informational: true},
		{fingerprint: "firefox", mlkem: true, informational: true},
		{fingerprint: "safari", mlkem: true, informational: true},
		{fingerprint: "", mlkem: true, informational: true},
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			originAddr := target.start(t)
			xrayPort := vmessInteropReserveTCPPort(t)
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			require.NoError(t, err)

			config := bpnMatrixXrayConfig(t, xrayPort.Port(), originAddr, privateKey)
			bpnMatrixStartXray(t, xrayBinary, config, xrayPort)
			bpnMatrixWarmUp(t, xrayPort.Port(), originAddr)

			for _, testCase := range testCases {
				name := testCase.fingerprint
				if name == "" {
					name = "empty"
				}
				if testCase.mlkem {
					name += "+support-x25519mlkem768"
				}
				t.Run(name, func(t *testing.T) {
					out, err := outbound.NewVless(outbound.VlessOption{
						Name:              "bpn_reality_matrix",
						Server:            "127.0.0.1",
						Port:              xrayPort.Port(),
						UUID:              bpnMatrixUUID,
						TLS:               true,
						ServerName:        "localhost",
						ClientFingerprint: testCase.fingerprint,
						RealityOpts: outbound.RealityOptions{
							PublicKey:             base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
							ShortID:               bpnMatrixShortID,
							SupportX25519MLKEM768: testCase.mlkem,
						},
					})
					if err == nil {
						t.Cleanup(func() { _ = out.Close() })
						err = bpnMatrixRoundTrip(out, echoAddr, t)
					}
					result := "ok"
					if err != nil {
						result = "fail: " + err.Error()
					}
					t.Logf("MATRIX xray=%s %s fp=%s -> %s", xrayVersion, target.name, name, result)
					if err != nil && !testCase.informational && !xrayRequiresMLKEM {
						t.Error(err)
					}
				})
			}
		})
	}
}

// bpnMatrixStartOpenSSLTarget runs "openssl s_server" as a REALITY target that
// only offers the given TLS 1.3 groups, e.g. the OpenSSL 3.0 default list
// (no X25519MLKEM768), like an nginx target built against OpenSSL 3.0.
func bpnMatrixStartOpenSSLTarget(t *testing.T, opensslBinary, groups string) string {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, []byte(certPEM), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte(keyPEM), 0o600))

	port := vmessInteropReserveTCPPort(t)
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port.Port()))
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, opensslBinary, "s_server", "-accept", address,
		"-cert", certPath, "-key", keyPath, "-tls1_3", "-groups", groups, "-www", "-quiet")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	port.Release()
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("openssl s_server exited: %v\n%s", err, output.String())
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return address
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("openssl s_server did not listen on %s\n%s", address, output.String())
	return ""
}

func bpnMatrixVersionAtLeast(t *testing.T, version string, major, minor, patch int) bool {
	t.Helper()
	var got [3]int
	_, err := fmt.Sscanf(version, "%d.%d.%d", &got[0], &got[1], &got[2])
	require.NoError(t, err, "parse Xray version %q", version)
	for i, want := range [3]int{major, minor, patch} {
		if got[i] != want {
			return got[i] > want
		}
	}
	return true
}

// bpnMatrixWarmUp waits until Xray has finished probing the target (Xray
// dials it on the first connection) with a plain TLS handshake that REALITY
// forwards to the target. openssl s_server serves one connection at a time,
// so without this the first matrix case can time out.
func bpnMatrixWarmUp(t *testing.T, xrayPort int, originAddr string) {
	t.Helper()
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(xrayPort))
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
		})
		if err == nil {
			_ = conn.Close()
			return
		}
		t.Logf("warm-up via %s (target %s): %v", address, originAddr, err)
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("REALITY server on %s did not forward to target %s", address, originAddr)
}

func bpnMatrixRoundTrip(out *outbound.Vless, echoAddr string, t *testing.T) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, vmessInteropMetadata(t, echoAddr))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	return vmessInteropRoundTripConn(conn, 64*1024)
}

func bpnMatrixXrayConfig(t *testing.T, port int, originAddr string, privateKey *ecdh.PrivateKey) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": bpnMatrixUUID}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					// "dest" is the pre-26 name of "target"; both are accepted.
					"dest":        originAddr,
					"serverNames": []string{"localhost"},
					"privateKey":  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
					"shortIds":    []string{bpnMatrixShortID},
					// minClientVer deliberately omitted: test the server default.
				},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{
				// Newer Xray blocks private destinations by default; the echo
				// server is loopback-only.
				"finalRules": []any{map[string]any{"action": "allow"}},
			},
		}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)
	return data
}

func bpnMatrixStartXray(t *testing.T, xrayBinary string, config []byte, port *vmessInteropReservedTCPPort) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "xray-reality.json")
	require.NoError(t, os.WriteFile(configPath, config, 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, xrayBinary, "run", "-c", configPath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	port.Release()
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() || testing.Verbose() {
			t.Log(bpnMatrixXrayLogTail(output.String()))
		}
	})

	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port.Port()))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("Xray exited before listening on %s: %v\n%s", address, err, output.String())
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Xray did not listen on %s\n%s", address, output.String())
}

func bpnMatrixXrayLogTail(log string) string {
	var lines []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "REALITY") || strings.Contains(line, "reality") || strings.Contains(line, "rejected") {
			lines = append(lines, line)
		}
	}
	if len(lines) > 40 {
		lines = lines[len(lines)-40:]
	}
	return "Xray REALITY log:\n" + strings.Join(lines, "\n")
}
