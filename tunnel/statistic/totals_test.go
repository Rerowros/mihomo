package statistic

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Resets race the writers and the scrapes: Totals never goes down and, at
// the end, equals every byte pushed; what the resets returned plus what is
// left in the counter adds up to the same.
func TestTotalsAgainstResets(t *testing.T) {
	const writers, pushes = 4, 20000
	users := &UserManager{users: make(map[UserKey]*userCounters)}
	inbounds := &InboundManager{inbounds: make(map[string]*inboundCounters)}
	key := UserKey{Inbound: "in", User: "u"}

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < pushes; j++ {
				users.PushUploaded(key, 1)
				users.PushDownloaded(key, 2)
				inbounds.PushUploaded("in", 1)
				inbounds.PushDownloaded("in", 2)
			}
		}()
	}

	stop := make(chan struct{})
	stopped := func() bool {
		select {
		case <-stop:
			return true
		default:
			return false
		}
	}
	var resetUp, resetDown, inResetUp, inResetDown atomic.Int64
	var others sync.WaitGroup
	others.Add(3)
	go func() { // the panel: Snapshot with reset and ResetTraffic, in turns
		defer others.Done()
		for n := 0; !stopped(); n++ {
			if n%2 == 0 {
				for _, s := range users.Snapshot("in", "u", true) {
					resetUp.Add(s.Upload)
					resetDown.Add(s.Download)
				}
			} else if up, down, ok := users.ResetTraffic("in", "u", true, true); ok {
				resetUp.Add(up)
				resetDown.Add(down)
			}
		}
	}()
	go func() { // the Xray API on the inbound
		defer others.Done()
		for !stopped() {
			if up, down, ok := inbounds.ResetTraffic("in", true, true); ok {
				inResetUp.Add(up)
				inResetDown.Add(down)
			}
		}
	}()
	var decreased atomic.Int64
	go func() { // the scrapes
		defer others.Done()
		var lastUp, lastDown, lastInUp, lastInDown int64
		for !stopped() {
			for _, u := range users.Totals() {
				if u.Upload < lastUp || u.Download < lastDown {
					decreased.Add(1)
				}
				lastUp, lastDown = u.Upload, u.Download
			}
			for _, s := range inbounds.Totals() {
				if s.Upload < lastInUp || s.Download < lastInDown {
					decreased.Add(1)
				}
				lastInUp, lastInDown = s.Upload, s.Download
			}
		}
	}()

	wg.Wait()
	close(stop)
	others.Wait()
	assert.Zero(t, decreased.Load(), "a total went down")

	const up, down = writers * pushes, 2 * writers * pushes
	ut := users.Totals()
	require.Len(t, ut, 1)
	assert.Equal(t, int64(up), ut[0].Upload)
	assert.Equal(t, int64(down), ut[0].Download)
	left := users.Snapshot("in", "u", false)[0]
	assert.Equal(t, int64(up), resetUp.Load()+left.Upload, "the resets plus what is left is every byte")
	assert.Equal(t, int64(down), resetDown.Load()+left.Download)

	it := inbounds.Totals()
	require.Len(t, it, 1)
	assert.Equal(t, int64(up), it[0].Upload)
	assert.Equal(t, int64(down), it[0].Download)
	inLeft := inbounds.Snapshot()[0]
	assert.Equal(t, int64(up), inResetUp.Load()+inLeft.Upload)
	assert.Equal(t, int64(down), inResetDown.Load()+inLeft.Download)
}
