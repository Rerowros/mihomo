package muxcool

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func collectServerFrames(conn net.Conn) <-chan Frame {
	frames := make(chan Frame, 256)
	go func() {
		defer close(frames)
		for {
			frame, err := DecodeFrame(conn)
			if err != nil {
				return
			}
			frames <- frame
		}
	}()
	return frames
}

// A target slower than the client upload must slow the carrier down, not
// lose data or end the stream (Xray and the old sing-vmess io.Pipe path
// block). The client End right after the burst must not drop queued data.
func TestServerStreamSlowTargetReceivesWholeUpload(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	received := make(chan int, 1)
	handler := testServerHandler{
		tcp: func(_ context.Context, conn net.Conn, _ M.Metadata) error {
			time.Sleep(300 * time.Millisecond)
			data, _ := io.ReadAll(conn)
			received <- len(data)
			return nil
		},
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return errors.New("unexpected UDP") },
	}
	carrier := serveTestCarrier(t, runtime, handler)
	frames := collectServerFrames(carrier)

	const chunks = 4 * serverStreamQueueSize
	chunk := make([]byte, 1024)
	writeTestFrame(t, carrier, Frame{
		SessionID: 1, Status: StatusNew, Option: OptionData, Network: NetworkTCP,
		Destination: "slow.example", Port: 80, Payload: chunk,
	})
	for i := 1; i < chunks; i++ {
		writeTestFrame(t, carrier, Frame{SessionID: 1, Status: StatusKeep, Option: OptionData, Payload: chunk})
	}
	writeTestFrame(t, carrier, Frame{SessionID: 1, Status: StatusEnd})

	select {
	case n := <-received:
		if n != chunks*len(chunk) {
			t.Fatalf("target received %d bytes, want %d", n, chunks*len(chunk))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target did not receive the upload")
	}
	for len(frames) > 0 {
		if frame := <-frames; frame.Status == StatusEnd && frame.Option&OptionError != 0 {
			t.Fatalf("server failed the stream: %+v", frame)
		}
	}
}

// Backpressure must not wedge the carrier: cancelling it (listener or runtime
// shutdown) while the reader is blocked on a full stream queue stops Serve.
func TestServerStreamBlockedQueueReleasedByCancel(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error {
			<-release
			return nil
		},
		udp: func(context.Context, N.PacketConn, M.Metadata) error { return errors.New("unexpected UDP") },
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	carrier, server := net.Pipe()
	t.Cleanup(func() { _ = carrier.Close() })
	served := make(chan struct{})
	go func() {
		_ = runtime.Serve(ctx, server, testCarrierMetadata(), handler)
		close(served)
	}()
	go func() {
		for range collectServerFrames(carrier) {
		}
	}()

	chunk := make([]byte, 1024)
	writeTestFrame(t, carrier, Frame{
		SessionID: 1, Status: StatusNew, Option: OptionData, Network: NetworkTCP,
		Destination: "stuck.example", Port: 80, Payload: chunk,
	})
	writes := make(chan error, 1)
	go func() {
		for i := 0; i < 4*serverStreamQueueSize; i++ {
			raw, err := EncodeFrame(Frame{SessionID: 1, Status: StatusKeep, Option: OptionData, Payload: chunk})
			if err == nil {
				err = writeFull(carrier, raw)
			}
			if err != nil {
				writes <- err
				return
			}
		}
		writes <- nil
	}()
	select {
	case err := <-writes:
		t.Fatalf("writes into a stuck stream did not block: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case <-writes:
	case <-time.After(time.Second):
		t.Fatal("blocked carrier not released by context cancel")
	}
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after context cancel")
	}
}

// UDP is lossy: a full queue drops datagrams but keeps the session.
func TestServerUDPQueueOverflowDropsPacketsAndKeepsSession(t *testing.T) {
	runtime := NewServerRuntime(ServerOptions{XUDPIdleTimeout: time.Hour})
	t.Cleanup(func() { _ = runtime.Close() })
	release := make(chan struct{})
	handler := testServerHandler{
		tcp: func(context.Context, net.Conn, M.Metadata) error { return errors.New("unexpected TCP") },
		udp: func(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
			<-release
			for {
				packet := buf.NewSize(MaxPayloadSize)
				destination, err := conn.ReadPacket(packet)
				if err != nil {
					packet.Release()
					return err
				}
				err = conn.WritePacket(packet, destination)
				packet.Release()
				if err != nil {
					return err
				}
			}
		},
	}
	carrier := serveTestCarrier(t, runtime, handler)
	frames := collectServerFrames(carrier)

	writeTestFrame(t, carrier, Frame{
		SessionID: 5, Status: StatusNew, Option: OptionData, Network: NetworkUDP,
		Destination: "dns.example", Port: 53, Payload: []byte("burst"),
	})
	for i := 0; i < 2*serverPacketQueueSize; i++ {
		writeTestFrame(t, carrier, Frame{
			SessionID: 5, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
			Destination: "dns.example", Port: 53, Payload: []byte("burst"),
		})
	}
	close(release)

	// Let the handler drain the queue, then the session must still work.
	const burst = 1 + 2*serverPacketQueueSize
	echoed := 0
	readEchoes := func(until string, wait time.Duration) bool {
		timeout := time.After(wait)
		for {
			select {
			case frame, ok := <-frames:
				if !ok {
					t.Fatal("carrier closed after UDP overflow")
				}
				if frame.SessionID != 5 {
					continue
				}
				if frame.Status == StatusEnd {
					t.Fatalf("UDP session ended after overflow: %+v (echoed %d)", frame, echoed)
				}
				if until != "" && string(frame.Payload) == until {
					return true
				}
				echoed++
			case <-timeout:
				return false
			}
		}
	}
	readEchoes("", 300*time.Millisecond)
	if echoed == 0 || echoed >= burst {
		t.Fatalf("echoed %d of %d burst packets, want some dropped", echoed, burst)
	}
	writeTestFrame(t, carrier, Frame{
		SessionID: 5, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "dns.example", Port: 53, Payload: []byte("after"),
	})
	if !readEchoes("after", 2*time.Second) {
		t.Fatal("UDP session did not echo after overflow")
	}
}
