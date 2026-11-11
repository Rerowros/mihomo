package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBPNConfigGracefullySkipsUnsupportedForkProxyOptions(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	raw := fmt.Sprintf(`
mixed-port: 0
mode: rule
unknown-root-option: true
proxies:
  - name: reality-bad-opts
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    servername: example.com
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    future-unknown-key: 42
    fragment-opts:
      packets: unsupported-mode
      length: "0-5"
    mux.cool:
      enabled: true
    reality-opts:
      public-key: %s
      short-id: 0102
      mlkem-client-fingerprint: edge
      client-version: "not-a-semver"

  - name: vmess-with-muxcool
    type: vmess
    server: 127.0.0.1
    port: 8443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    mux.cool:
      enabled: true

proxy-groups:
  - name: AUTO
    type: select
    proxies:
      - reality-bad-opts
      - vmess-with-muxcool

rules:
  - MATCH,AUTO
`, pub)

	cfg, err := Parse([]byte(raw))
	require.NoError(t, err)
	require.Contains(t, cfg.Proxies, "reality-bad-opts")
	require.Contains(t, cfg.Proxies, "vmess-with-muxcool")
	require.Contains(t, cfg.Proxies, "AUTO")
	for _, p := range cfg.Proxies {
		_ = p.Close()
	}
}
