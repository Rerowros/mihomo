package config_test

import (
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor" // provides config.temporaryUpdateGeneral
)

// S-2: a VLESS listener with duplicate users (name in another case, same id)
// does not reject the whole config: the duplicates are dropped, the first
// user is kept.
func TestParseVlessListenerDropsDuplicateUsers(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listeners:
  - name: vless-dup
    type: vless
    listen: 127.0.0.1
    port: 0
    users:
      - username: Alice
        uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
      - username: alice
        uuid: 11111111-2222-3333-4444-555555555555
      - username: bob
        uuid: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
`))
	if err != nil {
		t.Fatalf("config with duplicate VLESS users rejected: %v", err)
	}
	in, ok := cfg.Listeners["vless-dup"].(C.InboundUserManager)
	if !ok {
		t.Fatal("vless-dup listener missing or without a user table")
	}
	users := in.GetUsers()
	if len(users) != 1 || users[0].Username != "Alice" {
		t.Fatalf("users = %+v, want only Alice", users)
	}
}
