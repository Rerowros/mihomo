package xdrive

import (
	"context"
	"sync"
	"testing"
	"time"
)

type blockingStorage struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (s *blockingStorage) Put(ctx context.Context, name string, data []byte) error {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *blockingStorage) Get(context.Context, string) ([]byte, error) { return nil, errNotFound }
func (s *blockingStorage) Delete(context.Context, string) error        { return nil }
func (s *blockingStorage) List(context.Context, string) ([]Entry, error) {
	return nil, nil
}
func (s *blockingStorage) Close() error { return nil }

// A slow storage must stop Write from queueing segments without limit.
func TestWALWriterAppliesBackpressure(t *testing.T) {
	storage := &blockingStorage{started: make(chan struct{}), release: make(chan struct{})}
	writer := newWALWriter(context.Background(), storage, "s", params{
		segmentBytes:  1024,
		flushInterval: time.Hour,
		concurrency:   1,
	})

	if _, err := writer.Write(make([]byte, 1024)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	<-storage.started

	second := make(chan error, 1)
	go func() {
		_, err := writer.Write(make([]byte, 1024))
		second <- err
	}()
	select {
	case err := <-second:
		t.Fatalf("second write did not wait for the slot: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(storage.release)
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("second write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second write stayed blocked after the slot was freed")
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
