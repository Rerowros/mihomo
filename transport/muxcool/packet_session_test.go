package muxcool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPacketSessionWritesXrayUDPFrames(t *testing.T) {
	owner := newFakeSessionOwner()
	globalID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	packetConn, _ := newPacketSession(owner, 31, "initial.example", 53, globalID)
	t.Cleanup(func() { _ = packetConn.Close() })

	firstAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.8.8:53"))
	if n, err := packetConn.WriteTo([]byte("first"), firstAddr); err != nil || n != 5 {
		t.Fatalf("first WriteTo = (%d, %v)", n, err)
	}
	first := receiveFrame(t, owner.frames)
	if first.Status != StatusNew || first.Network != NetworkUDP || first.Destination != "initial.example" || first.Port != 53 {
		t.Fatalf("first frame target = %+v", first)
	}
	if first.GlobalID != globalID || string(first.Payload) != "first" {
		t.Fatalf("first frame = %+v", first)
	}

	secondAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::1]:5353"))
	if n, err := packetConn.WriteTo([]byte("second"), secondAddr); err != nil || n != 6 {
		t.Fatalf("second WriteTo = (%d, %v)", n, err)
	}
	second := receiveFrame(t, owner.frames)
	if second.Status != StatusKeep || second.Network != NetworkUDP || second.DestinationIP.String() != "2001:db8::1" || second.Port != 5353 {
		t.Fatalf("second frame target = %+v", second)
	}
	if second.GlobalID != [8]byte{} || string(second.Payload) != "second" {
		t.Fatalf("second frame = %+v", second)
	}
}

func TestPacketSessionPreservesDatagramBoundariesAndAddresses(t *testing.T) {
	owner := newFakeSessionOwner()
	packetConn, session := newPacketSession(owner, 32, "initial.example", 53, [8]byte{})
	t.Cleanup(func() { _ = packetConn.Close() })

	if err := session.deliverFrame(Frame{
		SessionID: 32, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "1.1.1.1", Port: 853, Payload: []byte("first-packet"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := session.deliverFrame(Frame{
		SessionID: 32, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "reply.example", Port: 5353, Payload: []byte("two"),
	}); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 5)
	n, addr, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buffer) || string(buffer) != "first" || addr.String() != "1.1.1.1:853" {
		t.Fatalf("first ReadFrom = (%d, %q, %v)", n, buffer, addr)
	}

	buffer = make([]byte, 16)
	n, addr, err = packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || string(buffer[:n]) != "two" || addr.String() != "reply.example:5353" {
		t.Fatalf("second ReadFrom = (%d, %q, %v)", n, buffer[:n], addr)
	}
}

func TestPacketSessionDeadlinesAndExplicitClose(t *testing.T) {
	owner := newFakeSessionOwner()
	packetConn, _ := newPacketSession(owner, 33, "cancel.example", 53, [8]byte{})

	if err := packetConn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := packetConn.ReadFrom(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("ReadFrom error = %v, want timeout", err)
	}
	if err := packetConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := packetConn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := packetConn.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.1.1.1:53"))); !isTimeout(err) {
		t.Fatalf("WriteTo error = %v, want timeout", err)
	}
	if err := packetConn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	if n, err := packetConn.WriteTo([]byte("alive"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("1.1.1.1:53"))); err != nil || n != len("alive") {
		t.Fatalf("WriteTo after clearing deadline = (%d, %v)", n, err)
	}
	data := receiveFrame(t, owner.frames)
	if data.Status != StatusNew || string(data.Payload) != "alive" {
		t.Fatalf("data after clearing deadline = %+v", data)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	end := receiveFrame(t, owner.frames)
	if end.Status != StatusEnd || end.SessionID != 33 {
		t.Fatalf("End = %+v", end)
	}
	select {
	case id := <-owner.removed:
		if id != 33 {
			t.Fatalf("removed ID = %d", id)
		}
	case <-time.After(time.Second):
		t.Fatal("packet session was not removed on Close")
	}
	select {
	case extra := <-owner.frames:
		t.Fatalf("unexpected extra frame: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}

// v2fly and older Xray servers send UDP responses without a target; the
// packet is from the session destination and the carrier must stay up.
func TestPacketSessionResponseWithoutTargetUsesSessionDestination(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })
	packetConn, err := worker.openPacketSession("8.8.8.8", 53, [8]byte{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })

	carrier.inject(t, Frame{SessionID: 1, Status: StatusKeep, Option: OptionData, Payload: []byte("answer")})
	_ = packetConn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 16)
	n, addr, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "answer" || addr.String() != "8.8.8.8:53" {
		t.Fatalf("ReadFrom = (%q, %v)", buffer[:n], addr)
	}
	if carrier.isClosed() || worker.activeSessions() != 1 {
		t.Fatalf("carrier closed = %t, active sessions = %d", carrier.isClosed(), worker.activeSessions())
	}
}

// An idle UDP session must not stall the carrier read loop: datagrams past
// its queue are dropped and the other sessions keep getting their data.
func TestPacketSessionFullQueueDoesNotBlockOtherSessions(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })
	packetConn, err := worker.openPacketSession("8.8.8.8", 53, [8]byte{})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := worker.openSession(context.Background(), "stream.example", 443, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close(); _ = packetConn.Close() })

	queue := cap(packetConn.(*packetSession).input)
	frames := make([][]byte, 0, queue*2+2)
	for i := 0; i < queue*2; i++ {
		raw, err := EncodeFrame(Frame{
			SessionID: 1, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
			Destination: "9.9.9.9", Port: 53, Payload: []byte(fmt.Sprintf("packet-%d", i)),
		})
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, raw)
	}
	for _, frame := range []Frame{
		{SessionID: 2, Status: StatusKeep, Option: OptionData, Payload: []byte("stream")},
		{SessionID: 1, Status: StatusEnd},
	} {
		raw, err := EncodeFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, raw)
	}

	// Nobody reads the UDP session while the frames arrive.
	streamRead := make(chan error, 1)
	go func() {
		for _, raw := range frames {
			if _, err := carrier.serverWriter.Write(raw); err != nil {
				streamRead <- err
				return
			}
		}
		got := make([]byte, len("stream"))
		if _, err := io.ReadFull(stream, got); err != nil {
			streamRead <- err
			return
		}
		if string(got) != "stream" {
			streamRead <- fmt.Errorf("stream = %q", got)
			return
		}
		streamRead <- nil
	}()
	select {
	case err := <-streamRead:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a full UDP session queue blocked the carrier read loop")
	}

	// The queued datagrams come in order, the rest were dropped, and
	// StatusEnd still closed the session.
	buffer := make([]byte, 32)
	for i := 0; i < queue; i++ {
		_ = packetConn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := packetConn.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("read datagram %d: %v", i, err)
		}
		if want := fmt.Sprintf("packet-%d", i); string(buffer[:n]) != want {
			t.Fatalf("datagram %d = %q, want %q", i, buffer[:n], want)
		}
	}
	_ = packetConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = packetConn.ReadFrom(buffer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after StatusEnd = %v, want net.ErrClosed", err)
	}
	if carrier.isClosed() {
		t.Fatal("carrier closed")
	}
}
