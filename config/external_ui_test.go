package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/observable"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

func TestExternalUIRefusesCoreDirectories(t *testing.T) {
	home := C.Path.HomeDir()
	for _, tc := range []struct {
		ui, name string
		ok       bool
	}{
		{"", "", true},
		{"ui", "", true},
		{"ui", "zashboard", true},
		{"", "metacubexd", true},
		{".", "", false},
		{"./", "", false},
		{home, "", false},
		{filepath.Dir(home), "", false},
		{".", "ui", false}, // external-ui itself is served by /ui
	} {
		err := CheckExternalUI(tc.ui, tc.name)
		if (err == nil) != tc.ok {
			t.Errorf("CheckExternalUI(%q, %q) = %v, want ok=%v", tc.ui, tc.name, err, tc.ok)
		}
	}
}

// A config with an external-ui that holds the core files still loads (a
// subscription may carry external-ui: ./): the UI is turned off with a warning.
func TestExternalUICoreDirectoryDisablesUI(t *testing.T) {
	home := C.Path.HomeDir()
	for _, ui := range []string{".", "./", home} {
		sub := log.Subscribe()
		ctrl, err := parseController(&RawConfig{ExternalUI: ui})
		warned := waitWarning(sub, "External UI disabled")
		log.UnSubscribe(sub)
		if err != nil {
			t.Errorf("external-ui %q: config refused: %v", ui, err)
			continue
		}
		if ctrl.ExternalUI != "" || ctrl.ExternalUIName != "" {
			t.Errorf("external-ui %q: kept as %q/%q, want the UI off", ui, ctrl.ExternalUI, ctrl.ExternalUIName)
		}
		if !warned {
			t.Errorf("external-ui %q: no warning in the log", ui)
		}
	}

	ctrl, err := parseController(&RawConfig{ExternalUI: "ui", ExternalUIName: "zashboard"})
	if err != nil {
		t.Fatal(err)
	}
	if ctrl.ExternalUI != "ui" || ctrl.ExternalUIName != "zashboard" {
		t.Errorf("safe external-ui = %q/%q, want it kept", ctrl.ExternalUI, ctrl.ExternalUIName)
	}
}

func waitWarning(sub observable.Subscription[log.Event], text string) bool {
	timeout := time.After(time.Second)
	for {
		select {
		case event := <-sub:
			if event.LogLevel == log.WARNING && strings.Contains(event.Payload, text) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}
