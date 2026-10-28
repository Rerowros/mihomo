package statistic

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimitManagerQuota(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	manager.Replace([]UserLimit{{Inbound: "in", User: "u", Quota: 100}})

	if _, err := manager.Admit(key); err != nil {
		t.Fatalf("fresh quota: %v", err)
	}
	if manager.AddUsage(key, 60) {
		t.Fatal("quota exhausted after 60 of 100")
	}
	if !manager.AddUsage(key, 60) {
		t.Fatal("quota not exhausted after 120 of 100")
	}
	if _, err := manager.Admit(key); !errors.Is(err, ErrUserQuotaExceeded) {
		t.Fatalf("admit over quota = %v", err)
	}
	if !manager.ResetQuota("in", "u") {
		t.Fatal("reset quota did not find the limit")
	}
	if _, err := manager.Admit(key); err != nil {
		t.Fatalf("admit after reset: %v", err)
	}
}

func TestLimitManagerConnsAndExpiry(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "u"}
	manager.Replace([]UserLimit{{Inbound: "in", User: "u", MaxConns: 1}})

	slot, err := manager.Admit(key)
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	if _, err := manager.Admit(key); !errors.Is(err, ErrUserMaxConns) {
		t.Fatalf("second admit = %v", err)
	}
	slot.Release()
	slot.Release() // idempotent: must not free a slot it does not hold
	next, err := manager.Admit(key)
	if err != nil {
		t.Fatalf("admit after release: %v", err)
	}
	if _, err := manager.Admit(key); !errors.Is(err, ErrUserMaxConns) {
		t.Fatalf("double release freed a second slot: %v", err)
	}
	next.Release()

	manager.Set(UserLimit{Inbound: "in", User: "expired", ExpireAt: time.Now().Add(-time.Second).Unix()})
	if _, err := manager.Admit(UserKey{Inbound: "in", User: "expired"}); !errors.Is(err, ErrUserLimitExpired) {
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

func TestRateLimiterSetRateWakesWaiters(t *testing.T) {
	limiter := newRateLimiter(1)
	done := make(chan struct{})
	go func() {
		limiter.wait(1000)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	limiter.setRate(0)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("setRate blocked for %v", elapsed)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wait did not wake after setRate")
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

// T10: removing a policy wakes a relay that is waiting on its rate.
func TestLimitManagerDeleteWakesWaiters(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "slow"}
	manager.Set(UserLimit{Inbound: "in", User: "slow", UpBps: 10})
	manager.WaitUpload(key, 1) // take the burst

	done := make(chan struct{})
	go func() {
		manager.WaitUpload(key, 10_000) // ~1000 s at 10 B/s
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	manager.Delete("in", "slow")
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waiter still sleeps after the policy was deleted")
	}

	manager.Set(UserLimit{Inbound: "in", User: "slow2", UpBps: 10})
	key2 := UserKey{Inbound: "in", User: "slow2"}
	manager.WaitUpload(key2, 1)
	done2 := make(chan struct{})
	go func() {
		manager.WaitUpload(key2, 10_000)
		close(done2)
	}()
	time.Sleep(50 * time.Millisecond)
	manager.Replace(nil)
	select {
	case <-done2:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waiter still sleeps after Replace dropped the policy")
	}
}

// T8: the max-conns check and the slot are one step, so parallel connections
// cannot all pass.
func TestLimitManagerAdmitIsAtomic(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "race"}
	manager.Set(UserLimit{Inbound: "in", User: "race", MaxConns: 2})
	var admitted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := manager.Admit(key); err == nil {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if admitted.Load() != 2 {
		t.Fatalf("admitted %d of 6, want 2", admitted.Load())
	}
}

// T9: a slot goes back to the policy state it was taken from.
func TestLimitManagerReleaseAfterPolicyReset(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "reset"}
	manager.Set(UserLimit{Inbound: "in", User: "reset", MaxConns: 1})
	s1, err := manager.Admit(key)
	if err != nil {
		t.Fatalf("s1: %v", err)
	}
	manager.Delete("in", "reset")
	manager.Set(UserLimit{Inbound: "in", User: "reset", MaxConns: 1})
	if _, err := manager.Admit(key); err != nil {
		t.Fatalf("s2: %v", err)
	}
	s1.Release()
	if _, err := manager.Admit(key); !errors.Is(err, ErrUserMaxConns) {
		t.Fatalf("third admit = %v: the old slot freed the new policy's slot", err)
	}
}

// M1: any policy counts connections, so /limits shows them and a max-conns
// set later sees the existing ones.
func TestLimitManagerCountsWithoutMaxConns(t *testing.T) {
	manager := newLimitManager()
	key := UserKey{Inbound: "in", User: "quota-only"}
	manager.Set(UserLimit{Inbound: "in", User: "quota-only", Quota: 1 << 30})
	slot, err := manager.Admit(key)
	if err != nil || slot == nil {
		t.Fatalf("admit = %v, %v", slot, err)
	}
	if got := manager.Snapshot("in", "quota-only")[0].Conns; got != 1 {
		t.Fatalf("conns = %d, want 1", got)
	}
	manager.Set(UserLimit{Inbound: "in", User: "quota-only", Quota: 1 << 30, MaxConns: 1})
	if _, err := manager.Admit(key); !errors.Is(err, ErrUserMaxConns) {
		t.Fatalf("admit after max-conns = %v", err)
	}
	if slot, err := newLimitManager().Admit(key); slot != nil || err != nil {
		t.Fatalf("no policy: admit = %v, %v", slot, err)
	}
}
