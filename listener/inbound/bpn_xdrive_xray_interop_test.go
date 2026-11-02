package inbound_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"

	"github.com/stretchr/testify/require"
)

// TestBPNXDriveXrayInterop runs the mihomo VLESS client over the xdrive
// transport against a local Xray-core xdrive server. Both peers exchange the
// segment objects through a shared local directory, so the test proves that
// the names, sequencing and framing match Xray byte for byte without any
// network service or cloud account.
//
//	xray vlessenc   # the decryption/encryption pair below is a test key
//	XRAY_BINARY=/path/to/xray go test ./listener/inbound -run BPNXDriveXrayInterop -v
func TestBPNXDriveXrayInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	xrayVersion := strings.Fields(string(versionOutput))[1]
	t.Logf("Xray executable: %s (%s)", xrayBinary, xrayVersion)

	const (
		uuid       = "11111111-2222-3333-4444-555555555555"
		decryption = "mlkem768x25519plus.native.600s.WOn7oTeoS5jk48uL_2M_iX0RA_1WMfp-gj7RaXmjsGw"
		encryption = "mlkem768x25519plus.native.0rtt.HH3NAmZ5OVFKB6IQvAgSI_AnH-8BfIHD-CYIStuBeWU"
	)

	storageDir := t.TempDir()
	target := bpnXHTTPStartTarget(t)

	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1",
			// xdrive has no socket; Xray still requires a port number here.
			"port":     19999,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": uuid, "flow": ""}},
				"decryption": decryption,
			},
			"streamSettings": map[string]any{
				"network":  "xdrive",
				"security": "none",
				"xdriveSettings": map[string]any{
					"service":           "local",
					"remoteFolder":      filepath.ToSlash(storageDir),
					"segmentBytes":      16384,
					"flushIntervalMs":   5,
					"pollIntervalMs":    10,
					"maxPollIntervalMs": 30,
					"eagerWindowMs":     20,
					"holeTimeoutMs":     5000,
					"sessionTtlSeconds": 60,
					"concurrency":       4,
				},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			// the echo target is on loopback, which freedom blocks by default
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	}
	configData, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	configPath := filepath.Join(t.TempDir(), "xray-xdrive.json")
	require.NoError(t, os.WriteFile(configPath, configData, 0o600))
	cmd := exec.CommandContext(ctx, xrayBinary, "run", "-c", configPath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Log("Xray log:\n" + output.String())
		}
	})
	select {
	case err := <-done:
		t.Fatalf("Xray exited before the test: %v\n%s", err, output.String())
	case <-time.After(time.Second):
	}

	out, err := outbound.NewVless(outbound.VlessOption{
		Name:       "bpn_xdrive_interop",
		Server:     "127.0.0.1",
		Port:       1, // xdrive does not dial it
		UUID:       uuid,
		Encryption: encryption,
		Network:    "xdrive",
		XDriveOpts: outbound.XDriveOptions{
			Service:           "local",
			RemoteFolder:      storageDir,
			SegmentBytes:      16384,
			FlushIntervalMs:   5,
			PollIntervalMs:    10,
			MaxPollIntervalMs: 30,
			EagerWindowMs:     20,
			HoleTimeoutMs:     5000,
			SessionTTLSeconds: 60,
			Concurrency:       4,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	conn := bpnXHTTPDial(t, out, target)
	defer conn.Close()

	up, err := bpnXHTTPUpload(conn, 1<<20)
	require.NoError(t, err)
	down, err := bpnXHTTPDownload(conn, 1<<20)
	require.NoError(t, err)
	t.Logf("THROUGHPUT xray=%s xdrive/local: up 1 MiB %.1f Mbit/s, down 1 MiB %.1f Mbit/s", xrayVersion, up, down)
}
