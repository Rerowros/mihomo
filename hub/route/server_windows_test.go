package route

import (
	"context"
	"fmt"
	stdnet "net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"

	"github.com/metacubex/http"
	"github.com/metacubex/wireguard-go/ipc/namedpipe"
)

func TestNamedPipeEnforcesSecret(t *testing.T) {
	t.Setenv("LISTEN_NAMEDPIPE_SDDL", "")
	path := fmt.Sprintf(`\\.\pipe\mihomo-route-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	l, err := inbound.ListenNamedPipe(path)
	if err != nil {
		t.Fatalf("ListenNamedPipe: %v", err)
	}
	server := &http.Server{Handler: newHandler(&Config{Secret: testSecret})}
	go func() { _ = server.Serve(l) }()
	defer server.Close()

	dial := func(ctx context.Context) (stdnet.Conn, error) {
		return namedpipe.DialContext(ctx, path)
	}
	if code := getStatus(t, dial, ""); code != http.StatusUnauthorized {
		t.Errorf("pipe GET / without token: got %d, want %d", code, http.StatusUnauthorized)
	}
	if code := getStatus(t, dial, testSecret); code != http.StatusOK {
		t.Errorf("pipe GET / with token: got %d, want %d", code, http.StatusOK)
	}
}

// startPipe is what ReCreateServer runs for external-controller-pipe: the
// pipe must ask for the secret like the tcp listener does.
func TestStartPipeEnforcesSecret(t *testing.T) {
	t.Setenv("LISTEN_NAMEDPIPE_SDDL", "")
	path := fmt.Sprintf(`\\.\pipe\mihomo-route-start-%d-%d`, os.Getpid(), time.Now().UnixNano())
	go startPipe(&Config{PipeAddr: path, Secret: testSecret})
	dial := func(ctx context.Context) (stdnet.Conn, error) {
		return namedpipe.DialContext(ctx, path)
	}
	dialUntilUp(t, dial)
	defer startPipe(&Config{})

	if code := getStatus(t, dial, ""); code != http.StatusUnauthorized {
		t.Errorf("pipe GET / without token: got %d, want %d", code, http.StatusUnauthorized)
	}
	if code := getStatus(t, dial, testSecret); code != http.StatusOK {
		t.Errorf("pipe GET / with token: got %d, want %d", code, http.StatusOK)
	}
}
