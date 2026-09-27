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

	"github.com/stretchr/testify/require"
)

const (
	bpnMatrixUUID    = "5f0c3a1e-8d7b-4c52-9a3e-2b6f1d4e7a90"
	bpnMatrixShortID = "0123456789abcdef"
)

// TestBPNRealityXrayMatrix connects mihomo VLESS+REALITY (tcp, no flow) to a
// local Xray-core REALITY server with a local TLS target, for each client
// fingerprint. No internet access is needed.
//
//	XRAY_BINARY=/path/to/xray go test ./listener/inbound -run BPNRealityXrayMatrix -v
//
// Every case logs a "MATRIX" line. edge (Edge 85, no ML-KEM) and the explicit
// support-x25519mlkem768 case are informational only: Xray >= 26.9.8 rejects
// ClientHellos without X25519MLKEM768 regardless of the client.
func TestBPNRealityXrayMatrix(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	xrayVersion := strings.Fields(string(versionOutput))[1]
	t.Logf("Xray executable: %s (%s)", xrayBinary, xrayVersion)

	origin := startTLSMirrorInteropCarrierTLS(t)
	echoAddr := startVMessInteropEcho(t)
	xrayPort := vmessInteropReserveTCPPort(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	config := bpnMatrixXrayConfig(t, xrayPort.Port(), origin.addr, privateKey)
	bpnMatrixStartXray(t, xrayBinary, config, xrayPort)

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
	}
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
			t.Logf("MATRIX xray=%s fp=%s -> %s", xrayVersion, name, result)
			if err != nil && !testCase.informational {
				t.Error(err)
			}
		})
	}
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
