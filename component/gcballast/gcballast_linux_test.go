//go:build linux && !android

package gcballast

import (
	"testing"

	"github.com/metacubex/mihomo/constant/features"
)

func TestBallastLeftOutWhenGCIsTuned(t *testing.T) {
	if features.CMFA {
		t.Skip("no ballast in CMFA builds")
	}
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	if !gcBallastWanted(env(nil)) {
		t.Fatal("no GOGC or GOMEMLIMIT: ballast not wanted")
	}
	if gcBallastWanted(env(map[string]string{"GOGC": "200"})) {
		t.Fatal("GOGC set: ballast wanted")
	}
	if gcBallastWanted(env(map[string]string{"GOMEMLIMIT": "512MiB"})) {
		t.Fatal("GOMEMLIMIT set: ballast wanted")
	}
}
