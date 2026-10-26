package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(dir string) *Config {
	return &Config{
		Service:         "local",
		RemoteFolder:    dir,
		SegmentBytes:    4096,
		FlushInterval:   5 * time.Millisecond,
		PollInterval:    10 * time.Millisecond,
		MaxPollInterval: 20 * time.Millisecond,
		EagerWindow:     20 * time.Millisecond,
		HoleTimeout:     2 * time.Second,
		SessionTTL:      time.Minute,
		Concurrency:     4,
	}
}

func TestLocalStorageRoundTrip(t *testing.T) {
	dir := t.TempDir()
	storage, err := newLocalStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := storage.Put(ctx, "streams/s1/c2s/000000000.seg", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := storage.Get(ctx, "streams/s1/c2s/000000000.seg")
	if err != nil || string(got) != "hello" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if _, err := storage.Get(ctx, "streams/s1/c2s/000000001.seg"); err != errNotFound {
		t.Fatalf("missing object returned %v", err)
	}
	entries, err := storage.List(ctx, "streams/s1/c2s")
	if err != nil || len(entries) != 1 || entries[0].Name != "000000000.seg" {
		t.Fatalf("List = %v, %v", entries, err)
	}
	if err := storage.Delete(ctx, "streams/s1/c2s/000000000.seg"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Get(ctx, "streams/s1/c2s/000000000.seg"); err != errNotFound {
		t.Fatalf("deleted object returned %v", err)
	}
}

func TestLocalStorageRejectsTraversal(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// path.Clean("/../../secret") = "/secret": the name is normalized into the
	// root instead of escaping it.
	full, err := storage.resolve("../../secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(full, storage.root+string(os.PathSeparator)) {
		t.Fatalf("resolved %q outside of %q", full, storage.root)
	}
	if _, err := storage.Get(context.Background(), "../../secret"); err != errNotFound {
		t.Fatalf("traversal object returned %v", err)
	}
}

// TestClientListenerLocal runs the whole transport through a local folder: the
// client announces a session, the listener accepts it, and bytes flow both ways.
func TestClientListenerLocal(t *testing.T) {
	ResetSharedStorage()
	t.Cleanup(ResetSharedStorage)

	cfg := testConfig(t.TempDir())
	accepted := make(chan net.Conn, 1)
	listener, err := Listen(cfg, func(conn net.Conn) { accepted <- conn })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, err := client.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the listener did not accept the session")
	}
	defer serverConn.Close()

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := readFull(t, serverConn, 4)
	if string(got) != "ping" {
		t.Fatalf("server read %q", got)
	}

	if _, err := serverConn.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	got = readFull(t, clientConn, 4)
	if string(got) != "pong" {
		t.Fatalf("client read %q", got)
	}
}

func TestClientListenerLargeTransfer(t *testing.T) {
	ResetSharedStorage()
	t.Cleanup(ResetSharedStorage)

	cfg := testConfig(t.TempDir())
	accepted := make(chan net.Conn, 1)
	listener, err := Listen(cfg, func(conn net.Conn) { accepted <- conn })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, err := client.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	payload := make([]byte, 512*1024+123)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	go func() { _, _ = clientConn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("server got %d bytes, want %d", len(got), len(payload))
	}

	// and the other direction over the same session
	resp := bytes.Repeat([]byte("s2c"), 100000)
	go func() { _, _ = serverConn.Write(resp) }()
	clientGot := make([]byte, len(resp))
	if _, err := io.ReadFull(clientConn, clientGot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientGot, resp) {
		t.Fatal("client did not receive the response")
	}
}

func TestParseAnnounce(t *testing.T) {
	now := time.Unix(0, 123456789)
	name := "123456789-0123456789abcdef"
	session, at, ok := parseAnnounce(name)
	if !ok || session != "0123456789abcdef" || !at.Equal(now) {
		t.Fatalf("parseAnnounce = %q, %v, %v", session, at, ok)
	}
	for _, bad := range []string{"", "-abc", "abc-", "abc-def", "1-", "-"} {
		if _, _, ok := parseAnnounce(bad); ok {
			t.Errorf("parseAnnounce(%q) accepted", bad)
		}
	}
}

func TestParseEntry(t *testing.T) {
	for name, want := range map[string]int64{
		"000000000.seg": 0,
		"000000042.end": 42,
		"000000007.err": 7,
	} {
		seq, ok := parseEntry(name)
		if !ok || seq != want {
			t.Errorf("parseEntry(%q) = %d, %v", name, seq, ok)
		}
	}
	for _, bad := range []string{"", ".seg", "abc.seg", "-1.seg", "1.bin"} {
		if _, ok := parseEntry(bad); ok {
			t.Errorf("parseEntry(%q) accepted", bad)
		}
	}
}

func readFull(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}
