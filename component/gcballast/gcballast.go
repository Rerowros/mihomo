//go:build !android && !ios

// Package gcballast raises the garbage collector's heap goal of a server
// build. Importing it is enough.
//
// Ported from getmikan/Citrus component/gcballast/gcballast.go (GPL-3.0).
package gcballast

import (
	"os"

	"github.com/metacubex/mihomo/constant/features"
)

// gcBallastSize is the size of the ballast, which raises the heap goal
// without using memory.
//
// The GC starts a cycle when the heap has grown by GOGC% of the live heap
// plus the globals. A server node keeps both small; under a stream of new
// connections, each of which allocates tens of kilobytes that die with it, a
// small goal means a GC cycle every few milliseconds. The ballast is one
// pointer-free allocation that is kept and never written: the GC counts it as
// live, so the goal grows by its size, but never scans it, and its pages are
// never touched, so it takes no RSS. It is counted in the heap metrics and
// against GOMEMLIMIT, so it is left out when GOGC or GOMEMLIMIT is set:
// whoever tunes the GC gets exactly what they set.
const gcBallastSize = 8 << 20

var gcBallast []byte

func init() {
	if gcBallastWanted(os.Getenv) {
		gcBallast = make([]byte, gcBallastSize)
	}
}

// Active reports whether the ballast was allocated.
func Active() bool { return gcBallast != nil }

func gcBallastWanted(getenv func(string) string) bool {
	return !features.CMFA && getenv("GOGC") == "" && getenv("GOMEMLIMIT") == ""
}
