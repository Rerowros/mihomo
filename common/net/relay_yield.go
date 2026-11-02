package net

import (
	"runtime"
	"time"
)

// A relay loop yields its processor (runtime.Gosched) once it has moved
// relayYieldBytes and run for relayYieldInterval since its last yield: a bulk
// loop that never blocks would otherwise hold a time slice while an
// interactive connection waits behind it in the run queue.
//
// Ported from getmikan/Citrus common/net/relay_yield.go (GPL-3.0).
const (
	relayYieldBytes    = 256 << 10
	relayYieldInterval = time.Millisecond
)

// relayYield tracks a relay loop since its last yield.
type relayYield struct {
	bytes int
	since time.Time
}

// add counts n more bytes and yields when both limits are reached.
func (y *relayYield) add(n int) {
	y.bytes += n
	if y.bytes < relayYieldBytes {
		return
	}
	now := time.Now()
	if y.since.IsZero() {
		y.since = now
		return
	}
	if now.Sub(y.since) < relayYieldInterval {
		return
	}
	y.bytes = 0
	runtime.Gosched()
	y.since = time.Now()
}
