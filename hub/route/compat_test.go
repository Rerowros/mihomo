package route

import (
	"bufio"
	"fmt"
	stdnet "net"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
)

// The clients of this fork talk to the controller in these ways; the
// hardening must keep every one of them working.

func resetServers(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ReCreateServer(&Config{})
		serverMu.Lock()
		applied = nil
		serverMu.Unlock()
	})
}

func controllerStatus(t *testing.T, addr, path, origin, token string) int {
	t.Helper()
	client := &stdhttp.Client{Timeout: 5 * time.Second, Transport: &stdhttp.Transport{DisableKeepAlives: true}}
	req, _ := stdhttp.NewRequest(stdhttp.MethodGet, "http://"+addr+path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// wsStatus opens a websocket the way the dashboards and the desktop client
// do: the secret in the token query parameter, no Authorization header.
func wsStatus(t *testing.T, addr, path, origin string) string {
	t.Helper()
	conn, err := stdnet.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	originHeader := ""
	if origin != "" {
		originHeader = "Origin: " + origin + "\r\n"
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n%sUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path, addr, originHeader)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("websocket %s: %v", path, err)
	}
	return strings.TrimSpace(status)
}

// The desktop client: 127.0.0.1 with a secret, bearer for REST, ?token= for
// the /traffic, /logs and /connections streams.
func TestDesktopClientLoopbackWithSecret(t *testing.T) {
	resetServers(t)
	addr := freeLoopbackAddr(t)
	ReCreateServer(&Config{Addr: addr, Secret: testSecret, Cors: Cors{AllowOrigins: []string{"*"}}})

	if code := controllerStatus(t, addr, "/version", "", testSecret); code != http.StatusOK {
		t.Errorf("GET /version with bearer: got %d, want 200", code)
	}
	if code := controllerStatus(t, addr, "/version", "", ""); code != http.StatusUnauthorized {
		t.Errorf("GET /version without bearer: got %d, want 401", code)
	}
	for _, path := range []string{"/traffic", "/logs", "/connections", "/memory"} {
		if status := wsStatus(t, addr, path+"?token="+testSecret, ""); !strings.Contains(status, "101") {
			t.Errorf("websocket %s with token query: %q, want 101", path, status)
		}
		if status := wsStatus(t, addr, path+"?token=wrong", ""); !strings.Contains(status, "401") {
			t.Errorf("websocket %s with a wrong token: %q, want 401", path, status)
		}
	}
}

// A loopback controller without a secret works as before for programs.
func TestLoopbackWithoutSecretUnchanged(t *testing.T) {
	resetServers(t)
	addr := freeLoopbackAddr(t)
	ReCreateServer(&Config{Addr: addr})
	if code := controllerStatus(t, addr, "/version", "", ""); code != http.StatusOK {
		t.Errorf("GET /version on loopback without secret: got %d, want 200", code)
	}
	if status := wsStatus(t, addr, "/traffic", ""); !strings.Contains(status, "101") {
		t.Errorf("websocket /traffic on loopback without secret: %q, want 101", status)
	}
}

// A dashboard (yacd, metacubexd, zashboard) served from another origin with
// the secret keeps working; without the secret a foreign origin is refused.
func TestDashboardOrigins(t *testing.T) {
	resetServers(t)
	addr := freeLoopbackAddr(t)
	const panel = "https://metacubex.github.io"
	ReCreateServer(&Config{Addr: addr, Secret: testSecret, Cors: Cors{AllowOrigins: []string{"*"}}})
	if code := controllerStatus(t, addr, "/proxies", panel, testSecret); code != http.StatusOK {
		t.Errorf("dashboard with the secret: got %d, want 200", code)
	}
	if status := wsStatus(t, addr, "/logs?token="+testSecret, panel); !strings.Contains(status, "101") {
		t.Errorf("dashboard websocket with the secret: %q, want 101", status)
	}

	ReCreateServer(&Config{Addr: addr, Cors: Cors{AllowOrigins: []string{"*"}}})
	if code := controllerStatus(t, addr, "/proxies", panel, ""); code != http.StatusForbidden {
		t.Errorf("foreign origin without a secret: got %d, want 403", code)
	}
	if status := wsStatus(t, addr, "/logs", panel); !strings.Contains(status, "403") {
		t.Errorf("foreign origin websocket without a secret: %q, want 403", status)
	}
}

// A server node: a network address needs a secret.
func TestNetworkAddressNeedsSecret(t *testing.T) {
	resetServers(t)
	ReCreateServer(&Config{Addr: "0.0.0.0:0"})
	serverMu.Lock()
	refused := httpServer == nil
	serverMu.Unlock()
	if !refused {
		t.Fatal("controller on 0.0.0.0 without a secret was started")
	}

	ReCreateServer(&Config{Addr: "0.0.0.0:0", Secret: testSecret})
	serverMu.Lock()
	started := httpServer != nil
	serverMu.Unlock()
	if !started {
		t.Fatal("controller on 0.0.0.0 with a secret was not started")
	}
}
