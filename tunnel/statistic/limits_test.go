package statistic

import (
	"errors"
	"testing"
	"time"
)

func TestLimitManagerQuota(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	manager.Replace([]UserLimit{{Inbound: "in", User: "u", Quota: 100}})

	if err := manager.Admit(key); err != nil {
		t.Fatalf("fresh quota: %v", err)
	}
	if manager.AddUsage(key, 60) {
		t.Fatal("quota exhausted after 60 of 100")
	}
	if !manager.AddUsage(key, 60) {
		t.Fatal("quota not exhausted after 120 of 100")
	}
	if err := manager.Admit(key); !errors.Is(err, ErrUserQuotaExceeded) {
		t.Fatalf("admit over quota = %v", err)
	}
	if !manager.ResetQuota("in", "u") {
		t.Fatal("reset quota did not find the limit")
	}
	if err := manager.Admit(key); err != nil {
		t.Fatalf("admit after reset: %v", err)
	}
}

func TestLimitManagerConnsAndExpiry(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	manager.Replace([]UserLimit{{Inbound: "in", User: "u", MaxConns: 1}})

	if err := manager.Admit(key); err != nil {
		t.Fatalf("first admit: %v", err)
	}
	manager.Connect(key)
	if err := manager.Admit(key); !errors.Is(err, ErrUserMaxConns) {
		t.Fatalf("second admit = %v", err)
	}
	manager.Disconnect(key)
	if err := manager.Admit(key); err != nil {
		t.Fatalf("admit after disconnect: %v", err)
	}

	manager.Set(UserLimit{Inbound: "in", User: "expired", ExpireAt: time.Now().Add(-time.Second).Unix()})
	if err := manager.Admit(UserKey{Inbound: "in", User: "expired"}); !errors.Is(err, ErrUserLimitExpired) {
		t.Fatalf("expired admit = %v", err)
	}
	if !manager.Expired(UserKey{Inbound: "in", User: "expired"}) {
		t.Fatal("expired limit not reported by Expired")
	}
	if manager.Expired(key) {
		t.Fatal("live limit reported expired")
	}
}

func TestLimitManagerSnapshot(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	manager.Replace([]UserLimit{{Inbound: "in", User: "u", Quota: 1000, DownBps: 1000}})
	manager.AddUsage(key, 250)

	statuses := manager.Snapshot("in", "u")
	if len(statuses) != 1 {
		t.Fatalf("statuses = %d", len(statuses))
	}
	if statuses[0].Used != 250 || statuses[0].Remaining != 750 {
		t.Fatalf("status = %+v", statuses[0])
	}
	if statuses[0].QuotaExceeded {
		t.Fatal("quota reported exhausted at 250 of 1000")
	}
}

func TestLimitManagerUpdatesRate(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	manager.Replace([]UserLimit{{Inbound: "in", User: "u", DownBps: 1000}})
	state := manager.lookup(key)
	if state == nil || state.down == nil || state.down.ratePerSecond() != 1000 {
		t.Fatalf("initial limiter = %+v", state)
	}
	manager.Set(UserLimit{Inbound: "in", User: "u", DownBps: 2000})
	state = manager.lookup(key)
	if state.down == nil || state.down.ratePerSecond() != 2000 {
		t.Fatalf("updated limiter rate = %v", state.down.ratePerSecond())
	}
}

func TestRateLimiterUnlimited(t *testing.T) {
	var limiter *rateLimiter
	start := time.Now()
	limiter.wait(1 << 20)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("nil limiter waited")
	}
}

func TestUserKeyOf(t *testing.T) {
	key, ok := UserKeyOf(nil)
	if ok {
		t.Fatalf("nil metadata returned %v", key)
	}
}
