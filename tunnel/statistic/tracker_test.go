package statistic

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type trackerTestConn struct {
	C.Conn
	closed atomic.Bool
}

func (c *trackerTestConn) Close() error              { c.closed.Store(true); return nil }
func (c *trackerTestConn) Chains() C.Chain           { return nil }
func (c *trackerTestConn) ProviderChains() C.Chain   { return nil }
func (c *trackerTestConn) RemoteDestination() string { return "" }

// testSession is a minimal C.InboundSession: Bind fails once revoked.
type testSession struct {
	mu      sync.Mutex
	revoked bool
	bound   map[io.Closer]struct{}
}

func (s *testSession) Revoked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

func (s *testSession) Bind(c io.Closer, _ bool) (func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return func() {}, false
	}
	if s.bound == nil {
		s.bound = map[io.Closer]struct{}{}
	}
	s.bound[c] = struct{}{}
	return func() {
		s.mu.Lock()
		delete(s.bound, c)
		s.mu.Unlock()
	}, true
}

// T6: a tracker created for a session revoked meanwhile is closed at once:
// it leaves the manager, closes its connection and frees its slot.
func TestTrackerOfRevokedSessionCloses(t *testing.T) {
	key := UserKey{Inbound: "tracker-in", User: "tracker-user"}
	DefaultLimitManager.Set(UserLimit{Inbound: key.Inbound, User: key.User, MaxConns: 1})
	defer DefaultLimitManager.Delete(key.Inbound, key.User)
	slot, err := DefaultLimitManager.Admit(key)
	if err != nil {
		t.Fatal(err)
	}

	session := &testSession{revoked: true}
	conn := &trackerTestConn{}
	metadata := &C.Metadata{InName: key.Inbound, InUser: key.User, InSession: session}
	tracker, err := NewTCPTrackerAdmitted(conn, DefaultManager, metadata, nil, 0, 0, true, slot)
	if err != C.ErrInboundUserRevoked {
		t.Fatalf("err = %v, want ErrInboundUserRevoked", err)
	}
	if DefaultManager.Get(tracker.ID()) != nil {
		t.Fatal("revoked tracker stays in the manager")
	}
	if !conn.closed.Load() {
		t.Fatal("revoked tracker did not close its connection")
	}
	next, err := DefaultLimitManager.Admit(key)
	if err != nil {
		t.Fatalf("slot not freed: %v", err)
	}
	next.Release()
}

// A live session binds the tracker and releases it on Close.
func TestTrackerBindsLiveSession(t *testing.T) {
	session := &testSession{}
	conn := &trackerTestConn{}
	metadata := &C.Metadata{InName: "tracker-in", InUser: "live", InSession: session}
	tracker, err := NewTCPTrackerAdmitted(conn, DefaultManager, metadata, nil, 0, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.bound) != 1 {
		t.Fatalf("bound = %d, want 1", len(session.bound))
	}
	_ = tracker.Close()
	if len(session.bound) != 0 {
		t.Fatalf("bound after close = %d, want 0", len(session.bound))
	}
}
