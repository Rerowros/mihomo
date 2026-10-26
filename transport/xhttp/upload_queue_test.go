package xhttp

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUploadQueueMaxPackets(t *testing.T) {
	q := NewUploadQueue(2)
	pushed := make(chan struct{})
	go func() {
		assert.NoError(t, q.Push(Packet{Seq: 0, Payload: []byte{'0'}}))
		assert.NoError(t, q.Push(Packet{Seq: 1, Payload: []byte{'1'}}))
		// the queue is full: the third Push waits for the reader
		assert.NoError(t, q.Push(Packet{Seq: 2, Payload: []byte{'2'}}))
		close(pushed)
	}()

	select {
	case <-pushed:
		t.Fatal("Push did not wait for the full queue")
	case <-time.After(50 * time.Millisecond):
	}

	buf := make([]byte, 20)
	for _, want := range []string{"0", "1", "2"} {
		n, err := q.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, want, string(buf[:n]))
	}

	select {
	case <-pushed:
	case <-time.After(time.Second):
		t.Fatal("Push still blocked after the reader consumed the queue")
	}

	require.NoError(t, q.Close())
}

func TestUploadQueueAdmitsNextSeqWhenFull(t *testing.T) {
	q := NewUploadQueue(2)
	// Out of order: the reader waits for seq 0 while 1 and 2 already fill the
	// map. Seq 0 must still be accepted, or both sides wait forever.
	require.NoError(t, q.Push(Packet{Seq: 1, Payload: []byte("1")}))
	require.NoError(t, q.Push(Packet{Seq: 2, Payload: []byte("2")}))

	done := make(chan error, 1)
	go func() { done <- q.Push(Packet{Seq: 0, Payload: []byte("0")}) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Push of the next seq blocked on a full queue")
	}

	buf := make([]byte, 4)
	for _, want := range []string{"0", "1", "2"} {
		n, err := q.Read(buf)
		require.NoError(t, err)
		require.Equal(t, want, string(buf[:n]))
	}
	require.NoError(t, q.Close())
}

// A retried GET (net/http may resend it on a reused connection) carries a seq
// the reader has already consumed. It must be dropped instead of taking space
// in the reassembly map forever.
func TestUploadQueueDropsConsumedSeq(t *testing.T) {
	q := NewUploadQueue(2)
	require.NoError(t, q.Push(Packet{Seq: 0, Payload: []byte("first")}))
	buf := make([]byte, 16)
	n, err := q.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "first", string(buf[:n]))

	require.NoError(t, q.Push(Packet{Seq: 0, Payload: []byte("retry")}))
	// a fresh seq still goes through and is not blocked by the stale retry
	require.NoError(t, q.Push(Packet{Seq: 1, Payload: []byte("second")}))
	n, err = q.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "second", string(buf[:n]))
	require.NoError(t, q.Close())
}

// Close unblocks a Push waiting for space.
func TestUploadQueueCloseUnblocksPush(t *testing.T) {
	q := NewUploadQueue(1)
	require.NoError(t, q.Push(Packet{Seq: 0, Payload: []byte{0}}))
	done := make(chan error, 1)
	go func() { done <- q.Push(Packet{Seq: 1, Payload: []byte{1}}) }()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, q.Close())
	select {
	case err := <-done:
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	case <-time.After(time.Second):
		t.Fatal("Push was not unblocked by Close")
	}
}
