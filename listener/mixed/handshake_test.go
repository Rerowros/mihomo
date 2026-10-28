package mixed

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	authStore "github.com/metacubex/mihomo/listener/auth"
)

func TestMixedHandshakeTimeoutSilentClient(t *testing.T) {
	old := authStore.HandshakeTimeout
	authStore.HandshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { authStore.HandshakeTimeout = old })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		handleConn(c, nil, authStore.Nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.Copy(io.Discard, client)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("server kept a silent conn open")
	}
}
