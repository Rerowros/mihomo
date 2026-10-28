package eventbus

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recv(t *testing.T, s *Subscription) Event {
	t.Helper()
	select {
	case e, ok := <-s.C():
		require.True(t, ok, "channel closed")
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
		return Event{}
	}
}

func noEvent(t *testing.T, s *Subscription) {
	t.Helper()
	select {
	case e := <-s.C():
		t.Fatalf("unexpected event %+v", e)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestParseTypes(t *testing.T) {
	m, err := ParseTypes("")
	require.NoError(t, err)
	assert.Equal(t, All, m)
	m, err = ParseTypes("user.session, user.limit")
	require.NoError(t, err)
	assert.Equal(t, bit(TypeUserSession)|bit(TypeUserLimit), m)
	_, err = ParseTypes("user.session,nope")
	assert.ErrorContains(t, err, "nope")
	_, err = ParseTypes(TypeDropped)
	assert.Error(t, err, "dropped is not a filter")
}

func TestFanOutAndFilter(t *testing.T) {
	b := New()
	assert.False(t, b.Enabled(TypeUserSession))
	b.Publish(TypeUserSession, "nobody listens") // no-op

	all := b.Subscribe(All, 8)
	session := b.Subscribe(bit(TypeUserSession), 8)
	limits := b.Subscribe(bit(TypeUserLimit), 8)
	assert.True(t, b.Enabled(TypeUserSession))
	assert.True(t, b.Enabled(TypeUserLimit))
	assert.False(t, b.Enabled("unknown"))

	b.Publish(TypeUserSession, 1)
	b.Publish(TypeUserLimit, 2)
	b.Publish(TypeConfigReload, 3)

	assert.Equal(t, 1, recv(t, all).Data)
	assert.Equal(t, 2, recv(t, all).Data)
	e := recv(t, all)
	assert.Equal(t, TypeConfigReload, e.Type)
	assert.False(t, e.Time.IsZero())
	assert.Equal(t, 1, recv(t, session).Data)
	noEvent(t, session)
	assert.Equal(t, 2, recv(t, limits).Data)
	noEvent(t, limits)

	assert.Equal(t, uint64(1), b.Published()[0])
	all.Close()
	session.Close()
	limits.Close()
	assert.False(t, b.Enabled(TypeUserSession))
	assert.Equal(t, 0, b.Subscribers())
}

func TestSlowSubscriberDrops(t *testing.T) {
	b := New()
	slow := b.Subscribe(All, 2)
	fast := b.Subscribe(All, 100)
	defer slow.Close()
	defer fast.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			b.Publish(TypeUserSession, i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	for i := 0; i < 10; i++ {
		assert.Equal(t, i, recv(t, fast).Data)
	}
	assert.Equal(t, 0, recv(t, slow).Data)
	assert.Equal(t, 1, recv(t, slow).Data)
	noEvent(t, slow)
	assert.Equal(t, uint64(8), slow.TakeDropped())
	assert.Equal(t, uint64(0), slow.TakeDropped(), "taken")
	assert.Equal(t, uint64(0), fast.TakeDropped())
	assert.Equal(t, uint64(8), b.Dropped())
}

func TestUnsubscribe(t *testing.T) {
	b := New()
	before := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		s := b.Subscribe(bit(TypeUserSession), 4)
		b.Publish(TypeUserSession, i)
		s.Close()
		s.Close() // idempotent
		_, ok := <-s.C()
		assert.True(t, ok, "buffered event still readable")
		_, ok = <-s.C()
		assert.False(t, ok, "closed")
	}
	b.Publish(TypeUserSession, "after") // no subscriber, no panic on a closed channel
	assert.Equal(t, 0, b.Subscribers())
	assert.False(t, b.Enabled(TypeUserSession))
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "the bus starts no goroutines")

	// closing while publishing concurrently
	s := b.Subscribe(All, 1)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				b.Publish(TypeUserSession, 0)
			}
		}
	}()
	time.Sleep(5 * time.Millisecond)
	s.Close()
	close(stop)
}
