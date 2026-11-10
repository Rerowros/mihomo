package gcballast

import (
	"os"
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/constant/features"
)

// The ballast is for Linux server nodes only: clients on Windows, macOS and
// mobile must not get it.
func TestBallastOnlyOnLinux(t *testing.T) {
	want := runtime.GOOS == "linux" && !features.CMFA && os.Getenv("GOGC") == "" && os.Getenv("GOMEMLIMIT") == ""
	if Active() != want {
		t.Fatalf("Active() = %t on %s, want %t", Active(), runtime.GOOS, want)
	}
}
