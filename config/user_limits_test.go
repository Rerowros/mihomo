package config_test

import (
	"testing"

	"github.com/metacubex/mihomo/config"
	_ "github.com/metacubex/mihomo/hub/executor" // provides config.temporaryUpdateGeneral
)

// max-ips is read next to max-conns.
func TestParseUserLimitsMaxIPs(t *testing.T) {
	cfg, err := config.Parse([]byte(`
user-limits:
  - inbound: in
    user: alice
    max-conns: 4
    max-ips: 2
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.UserLimits) != 1 {
		t.Fatalf("limits = %+v", cfg.UserLimits)
	}
	if got := cfg.UserLimits[0]; got.MaxConns != 4 || got.MaxIPs != 2 {
		t.Fatalf("limit = %+v", got)
	}
}
