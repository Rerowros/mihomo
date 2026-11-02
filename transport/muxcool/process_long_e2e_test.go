//go:build integration

package muxcool_test

import (
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"
)

// mihomo process (tunnel) -> mux.cool -> Xray server. tunnel dials with a
// C.DefaultTCPTimeout (5 s) context; the TCP connection must survive idling
// past it.
func TestMuxCoolLongLivedTCPThroughTunnel(t *testing.T) {
	mihomoBinary := buildMihomoProcessE2E(t)
	xrayBinary := buildXrayProcessE2E(t)
	tcpAddress, _ := startProcessE2EEcho(t)
	serverPort := reserveProcessE2EPort(t)
	clientPort := reserveProcessE2EPort(t)
	tempDir := t.TempDir()
	serverConfig := filepath.Join(tempDir, "xray-server.json")
	clientConfig := filepath.Join(tempDir, "mihomo-client.yaml")
	writeProcessE2EFile(t, serverConfig, xrayServerProcessE2EConfig(serverPort))
	writeProcessE2EFile(t, clientConfig, mihomoClientProcessE2EConfig(clientPort, serverPort, 0))
	server := startXrayProcessE2E(t, xrayBinary, serverConfig, nil)
	waitProcessE2ETCP(t, server, fmt.Sprintf("127.0.0.1:%d", serverPort))
	client := startMihomoProcessE2E(t, mihomoBinary, clientConfig, filepath.Join(tempDir, "mihomo-home"))
	clientAddress := fmt.Sprintf("127.0.0.1:%d", clientPort)
	waitProcessE2ETCP(t, client, clientAddress)

	var conn interface {
		io.ReadWriteCloser
		SetDeadline(time.Time) error
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r := <-startProcessE2EWave(clientAddress, tcpAddress, 0, 1)
		if r.err == nil {
			conn = r.connection
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("no first round trip")
	}
	defer conn.Close()
	t.Log("first round trip ok, idling 7s")
	time.Sleep(7 * time.Second)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("again")); err != nil {
		t.Fatalf("write after 7s: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read after 7s: %v", err)
	}
	t.Logf("second round trip ok: %q", buf)
}
