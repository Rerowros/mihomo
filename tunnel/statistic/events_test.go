package statistic

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func subscribe(t *testing.T, types string, size int) *eventbus.Subscription {
	t.Helper()
	mask, err := eventbus.ParseTypes(types)
	require.NoError(t, err)
	s := eventbus.Subscribe(mask, size)
	t.Cleanup(s.Close)
	return s
}

// nextEvent returns the next event of inbound, skipping the events of other
// tests' inbounds.
func nextEvent(t *testing.T, s *eventbus.Subscription, inbound string) eventbus.Event {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case e := <-s.C():
			switch d := e.Data.(type) {
			case eventbus.UserSession:
				if d.Inbound == inbound {
					return e
				}
			case eventbus.UserLimit:
				if d.Inbound == inbound {
					return e
				}
			}
		case <-timeout:
			t.Fatal("no event")
			return eventbus.Event{}
		}
	}
}

func noEventOf(t *testing.T, s *eventbus.Subscription, inbound string) {
	t.Helper()
	for {
		select {
		case e := <-s.C():
			if d, ok := e.Data.(eventbus.UserSession); ok && d.Inbound == inbound {
				t.Fatalf("unexpected event %+v", e)
			}
			if d, ok := e.Data.(eventbus.UserLimit); ok && d.Inbound == inbound {
				t.Fatalf("unexpected event %+v", e)
			}
		case <-time.After(50 * time.Millisecond):
			return
		}
	}
}

func TestUserSessionEvents(t *testing.T) {
	const inbound = "events-session-in"
	s := subscribe(t, eventbus.TypeUserSession, 16)
	metadata := func() *C.Metadata {
		return &C.Metadata{InName: inbound, InUser: "alice", SrcIP: netip.MustParseAddr("::ffff:192.0.2.10")}
	}

	first, err := NewTCPTrackerAdmitted(&trackerTestConn{}, DefaultManager, metadata(), nil, 0, 0, true, nil)
	require.NoError(t, err)
	e := nextEvent(t, s, inbound)
	assert.Equal(t, eventbus.TypeUserSession, e.Type)
	assert.Equal(t, eventbus.UserSession{Inbound: inbound, User: "alice", State: eventbus.SessionOnline, Remote: "192.0.2.10"}, e.Data)

	second, err := NewUDPTrackerAdmitted(&trackerTestPacketConn{}, DefaultManager, metadata(), nil, 0, 0, true, nil)
	require.NoError(t, err)
	noEventOf(t, s, inbound) // already online

	_ = first.Close()
	noEventOf(t, s, inbound) // one connection left
	_ = second.Close()
	_ = second.Close() // a second Close does not report twice
	e = nextEvent(t, s, inbound)
	assert.Equal(t, eventbus.UserSession{Inbound: inbound, User: "alice", State: eventbus.SessionOffline}, e.Data)
	noEventOf(t, s, inbound)
}

func TestUserLimitRejectedEvents(t *testing.T) {
	old := rejectEventInterval
	rejectEventInterval = 100 * time.Millisecond
	t.Cleanup(func() { rejectEventInterval = old })

	const inbound = "events-limit-in"
	key := UserKey{Inbound: inbound, User: "bob"}
	m := newLimitManager()
	m.Set(UserLimit{Inbound: inbound, User: "bob", MaxConns: 1})
	s := subscribe(t, eventbus.TypeUserLimit, 16)

	slot, err := m.Admit(key)
	require.NoError(t, err)
	defer slot.Release()
	noEventOf(t, s, inbound)

	_, err = m.Admit(key)
	require.ErrorIs(t, err, ErrUserMaxConns)
	e := nextEvent(t, s, inbound)
	assert.Equal(t, eventbus.UserLimit{Inbound: inbound, User: "bob", Reason: RejectMaxConns, Action: eventbus.LimitRejected}, e.Data)

	// a client retrying in a loop is reported once per interval
	for i := 0; i < 5; i++ {
		_, err = m.Admit(key)
		require.ErrorIs(t, err, ErrUserMaxConns)
	}
	noEventOf(t, s, inbound)
	time.Sleep(rejectEventInterval)
	_, err = m.Admit(key)
	require.ErrorIs(t, err, ErrUserMaxConns)
	e = nextEvent(t, s, inbound)
	assert.Equal(t, int64(5), e.Data.(eventbus.UserLimit).Suppressed)
}

func TestUserLimitClosedEvents(t *testing.T) {
	const inbound = "events-closed-in"
	quotaKey := UserKey{Inbound: inbound, User: "carol"}
	expiredKey := UserKey{Inbound: inbound, User: "dave"}
	m := newLimitManager()
	m.Set(UserLimit{Inbound: inbound, User: "carol", Quota: 10})
	m.Set(UserLimit{Inbound: inbound, User: "dave", ExpireAt: time.Now().Add(-time.Minute).Unix()})
	s := subscribe(t, eventbus.TypeUserLimit, 16)

	assert.False(t, m.AddUsage(quotaKey, 5))
	noEventOf(t, s, inbound)
	assert.True(t, m.AddUsage(quotaKey, 6))
	e := nextEvent(t, s, inbound)
	assert.Equal(t, eventbus.UserLimit{Inbound: inbound, User: "carol", Reason: RejectQuota, Action: eventbus.LimitClosed}, e.Data)
	assert.True(t, m.AddUsage(quotaKey, 1))
	noEventOf(t, s, inbound) // reported once, when the quota was crossed

	assert.True(t, m.Expired(expiredKey))
	e = nextEvent(t, s, inbound)
	assert.Equal(t, eventbus.UserLimit{Inbound: inbound, User: "dave", Reason: RejectExpired, Action: eventbus.LimitClosed}, e.Data)
	assert.True(t, m.Expired(expiredKey))
	noEventOf(t, s, inbound) // once per expire-at
}

// A subscriber that never reads must not slow the connection path down: the
// events that do not fit its buffer are dropped for it.
func TestSlowSubscriberDoesNotBlockTrackers(t *testing.T) {
	const inbound = "events-slow-in"
	s := subscribe(t, eventbus.TypeUserSession, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			tracker, _ := NewTCPTrackerAdmitted(&trackerTestConn{}, DefaultManager, &C.Metadata{InName: inbound, InUser: "erin"}, nil, 0, 0, true, nil)
			_ = tracker.Close()
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		go func() { // unblock the publisher, so the cleanup can unsubscribe
			for range s.C() {
			}
		}()
		t.Fatal("trackers blocked on a slow subscriber")
	}
	assert.Equal(t, uint64(1999), s.TakeDropped(), "one online fits the buffer, the rest is dropped")
}
