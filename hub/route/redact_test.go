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
