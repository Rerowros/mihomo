package muxcool

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// tunnel.handleTCPConn dials with context.WithTimeout(C.DefaultTCPTimeout) and
// keeps that context until the relay ends. The deadline must bound opening
// only, not the lifetime of an established mux.cool stream.
func TestPoolStreamOutlivesExpiredDialContext(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	pool := NewPool(dialer.dial, testPoolOptions())
	t.Cleanup(func() { _ = pool.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conn, err := pool.DialContext(ctx, "long.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	<-ctx.Done()
	time.Sleep(100 * time.Millisecond)

	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("up")); err != nil {
		t.Fatalf("write after dial context expired: %v", err)
	}
	carrier := dialer.carriers[0]
	carrier.inject(t, Frame{SessionID: 1, Status: StatusKeep, Option: OptionData, Payload: []byte("down")})
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len("down"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read after dial context expired: %v", err)
	}
	if string(got) != "down" {
		t.Fatalf("downlink = %q", got)
	}
	if carrier.isClosed() {
		t.Fatal("carrier closed after dial context expired")
	}
}

func TestPoolDialWithCancelledContextOpensNoSession(t *testing.T) {
	dialer := &fakeCarrierDialer{}
	pool := NewPool(dialer.dial, testPoolOptions())
	t.Cleanup(func() { _ = pool.Close() })

	warm, err := pool.DialContext(context.Background(), "warm.example", 80)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = warm.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := pool.DialContext(ctx, "cancelled.example", 80); !errors.Is(err, context.Canceled) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("dial with cancelled context error = %v", err)
	}
	if active := pool.workers[0].activeSessions(); active != 1 {
		t.Fatalf("active sessions = %d, want 1", active)
	}
}

func TestWorkerOpenSessionRejectsCancelledContext(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := worker.openSession(ctx, "cancelled.example", 80, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("open with cancelled context error = %v", err)
	}
	if active := worker.activeSessions(); active != 0 {
		t.Fatalf("active sessions = %d, want 0", active)
	}
}
