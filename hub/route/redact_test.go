package route

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/config"
	LC "github.com/metacubex/mihomo/listener/config"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestRedactGeneral(t *testing.T) {
	ss := LC.ShadowsocksServer{
		Enable:   true,
		Listen:   "0.0.0.0:8388",
		Password: "server-ipsk",
		Cipher:   "2022-blake3-aes-128-gcm",
		ShadowTLS: LC.ShadowTLS{
			Enable:   true,
			Password: "stls-pass",
			Users:    []LC.ShadowTLSUser{{Name: "bob", Password: "bob-stls"}},
		},
		ResTLS:    LC.ResTLS{Enable: true, Password: "restls-pass"},
		JLSConfig: LC.JLSConfig{Enable: true, Users: []LC.JLSUser{{Username: "alice", Password: "alice-jls"}}},
	}
	ss.KcpTun.Enable = true
	ss.KcpTun.Key = "kcp-key"
	vmess := LC.VmessServer{
		Enable:     true,
		Listen:     "0.0.0.0:10086",
		Users:      []LC.VmessUser{{Username: "carol", UUID: "11111111-2222-3333-4444-555555555555"}},
		PrivateKey: "vmess-private-key",
	}
	users := map[string]string{"00000000-0000-0000-0000-000000000001": "tuic-pass"}
	tokens := []string{"tuic-token"}
	g := &config.General{Inbound: config.Inbound{
		TuicServer: LC.TuicServer{
			Enable:      true,
			Listen:      "0.0.0.0:443",
			Token:       tokens,
			Users:       users,
			Certificate: "cert.pem",
			PrivateKey:  "-----BEGIN PRIVATE KEY-----\ninline\n-----END PRIVATE KEY-----",
			EchKey:      "ech-secret",
		},
		ShadowSocksConfig: ss.String(),
		VmessConfig:       vmess.String(),
	}}

	redactGeneral(g)

	out, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"server-ipsk", "stls-pass", "bob-stls", "restls-pass", "alice-jls", "kcp-key", "11111111-2222-3333-4444-555555555555", "vmess-private-key", "tuic-pass", "tuic-token", "inline", "ech-secret"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("GET /configs still contains %q: %s", secret, out)
		}
	}
	for _, kept := range []string{"0.0.0.0:8388", "2022-blake3-aes-128-gcm", "alice", "carol", "0.0.0.0:10086", "00000000-0000-0000-0000-000000000001", "cert.pem"} {
		if !strings.Contains(string(out), kept) {
			t.Errorf("GET /configs lost %q: %s", kept, out)
		}
	}
	// The live configuration is not touched.
	if tokens[0] != "tuic-token" || users["00000000-0000-0000-0000-000000000001"] != "tuic-pass" {
		t.Error("redaction changed the running TUIC configuration")
	}

	if got := redactJSONString("not json"); got != redacted {
		t.Errorf("unparsable ss-config = %q, want it redacted", got)
	}
	if got := redactJSONString(""); got != "" {
		t.Errorf("empty ss-config = %q", got)
	}
}

// GET /configs is what dashboards read; it must carry neither the controller
// secret nor the inbound credentials.
func TestGetConfigsHasNoSecret(t *testing.T) {
	h := router(false, testSecret, "", Cors{})
	req := httptest.NewRequest(http.MethodGet, "/configs", nil)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /configs: got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), testSecret) {
		t.Errorf("GET /configs contains the controller secret: %s", rec.Body.String())
	}
}

// A dashboard that reads GET /configs and sends it back with PATCH /configs
// must not overwrite the credentials with the mask.
func TestPatchConfigsKeepsRedactedCredentials(t *testing.T) {
	ss := LC.ShadowsocksServer{
		Enable:   true,
		Listen:   "0.0.0.0:8388",
		Password: "server-ipsk",
		Cipher:   "2022-blake3-aes-128-gcm",
	}
	tuic := LC.TuicServer{
		Enable:      true,
		Listen:      "0.0.0.0:443",
		Token:       []string{"tuic-token"},
		Users:       map[string]string{"user-1": "tuic-pass"},
		Certificate: "cert.pem",
		PrivateKey:  "tuic-private-key",
	}
	g := &config.General{Inbound: config.Inbound{
		TuicServer:        tuic,
		ShadowSocksConfig: ss.String(),
	}}
	g.TuicServer.Token = append([]string(nil), tuic.Token...)
	g.TuicServer.Users = map[string]string{"user-1": "tuic-pass"}
	redactGeneral(g)
	body, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var patch configSchema
	if err := json.Unmarshal(body, &patch); err != nil {
		t.Fatal(err)
	}

	got := pointerOrDefaultTuicServer(patch.TuicServer, tuic)
	if len(got.Token) != 1 || got.Token[0] != "tuic-token" {
		t.Errorf("tuic token = %q, want the current one", got.Token)
	}
	if got.Users["user-1"] != "tuic-pass" {
		t.Errorf("tuic users = %v, want the current password", got.Users)
	}
	if got.PrivateKey != "tuic-private-key" {
		t.Errorf("tuic private-key = %q, want the current one", got.PrivateKey)
	}
	if got := restoreJSONString(*patch.ShadowSocksConfig, ss.String()); got != ss.String() {
		t.Errorf("ss-config = %q, want the current %q", got, ss.String())
	}

	// New values next to masked ones: the new ones apply, the masked ones keep
	// the current value, a masked value without a current one is dropped.
	edited := &tuicServerSchema{
		Enable:     true,
		Token:      &[]string{redacted, "new-token", redacted},
		Users:      &map[string]string{"user-1": redacted, "user-2": "pass-2", "user-3": redacted},
		PrivateKey: new(string),
	}
	*edited.PrivateKey = "new-key"
	got = pointerOrDefaultTuicServer(edited, tuic)
	if strings.Join(got.Token, ",") != "tuic-token,new-token" {
		t.Errorf("edited tuic token = %q", got.Token)
	}
	if len(got.Users) != 2 || got.Users["user-1"] != "tuic-pass" || got.Users["user-2"] != "pass-2" {
		t.Errorf("edited tuic users = %v", got.Users)
	}
	if got.PrivateKey != "new-key" {
		t.Errorf("edited tuic private-key = %q", got.PrivateKey)
	}
	moved := strings.Replace(*patch.ShadowSocksConfig, "0.0.0.0:8388", "0.0.0.0:9388", 1)
	restored := restoreJSONString(moved, ss.String())
	if !strings.Contains(restored, "0.0.0.0:9388") || !strings.Contains(restored, "server-ipsk") || strings.Contains(restored, redacted) {
		t.Errorf("edited ss-config = %q, want the new listen and the current password", restored)
	}

	// Values without the mask are applied as they are.
	if got := restoreJSONString(`{"password":"p"}`, ss.String()); got != `{"password":"p"}` {
		t.Errorf("plain ss-config = %q", got)
	}
	// A mask that matches nothing keeps the running configuration.
	if got := restoreJSONString(`{"other":"`+redacted+`"}`, ss.String()); got != ss.String() {
		t.Errorf("unmatched mask in ss-config = %q, want the current one", got)
	}
}
