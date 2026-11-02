package anytls

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

// shortHandshakeTimeout shortens handshakeTimeout for one test.
func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := handshakeTimeout
	handshakeTimeout = d
	t.Cleanup(func() { handshakeTimeout = old })
}

// serveAnyTLSOnce accepts one TCP connection and serves it with l.HandleConn.
func serveAnyTLSOnce(t *testing.T, l *Listener) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		l.HandleConn(c, nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func expectClosedWithin(t *testing.T, client net.Conn, limit time.Duration) {
	t.Helper()
	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(limit))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept the unauthenticated conn open for %v", limit)
	}
	if err == nil {
		t.Fatal("server sent data to an unauthenticated client")
	}
	t.Logf("closed after %v: %v", time.Since(start), err)
}

func TestAnyTLSHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveAnyTLSOnce(t, &Listener{userMap: map[[32]byte]string{}})
	expectClosedWithin(t, client, 3*time.Second)
}

func anytlsFrame(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}

// An authenticated client that opens a stream and never sends its
// destination must not hold the stream's goroutine forever.
func TestAnyTLSStreamDestinationTimeout(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	const password = "anytls-test-password"
	paddingFactory := padding.NewPaddingFactory(padding.DefaultPaddingScheme)
	l := &Listener{userMap: map[[32]byte]string{sha256.Sum256([]byte(password)): "test"}}
	l.padding.Store(paddingFactory)
	client := serveAnyTLSOnce(t, l)

	const (
		cmdSYN      = 1
		cmdFIN      = 3
		cmdSettings = 4
	)
	sum := sha256.Sum256([]byte(password))
	prelude := append(sum[:], 0, 0) // no padding
	settings := util.StringMap{"v": "1", "client": "test", "padding-md5": paddingFactory.Md5}
	prelude = append(prelude, anytlsFrame(cmdSettings, 0, settings.ToBytes())...)
	prelude = append(prelude, anytlsFrame(cmdSYN, 1, nil)...)
	if _, err := client.Write(prelude); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var hdr [7]byte
	for {
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			t.Fatalf("stream 1 was not closed: %v", err)
		}
		data := make([]byte, binary.BigEndian.Uint16(hdr[5:7]))
		if _, err := io.ReadFull(client, data); err != nil {
			t.Fatal(err)
		}
		if hdr[0] == cmdFIN && binary.BigEndian.Uint32(hdr[1:5]) == 1 {
			break
		}
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("stream closed after %v, before the handshake timeout", elapsed)
	}
}
