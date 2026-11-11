package adapter

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/fragment"

	"github.com/stretchr/testify/require"
)

func bpnVlessMapping(fragmentOpts any) map[string]any {
	m := map[string]any{
		"name": "n", "type": "vless", "server": "127.0.0.1", "port": 443,
		"uuid": "11111111-2222-3333-4444-555555555555", "tls": true, "servername": "example.com",
	}
	if fragmentOpts != nil {
		m["fragment-opts"] = fragmentOpts
	}
	return m
}

func TestBPNParseProxyFragmentOpts(t *testing.T) {
	p, err := ParseProxy(bpnVlessMapping(nil))
	require.NoError(t, err)
	_ = p.Close()

	// YAML numbers are accepted where Xray accepts them.
	p, err = ParseProxy(bpnVlessMapping(map[string]any{"packets": "tlshello", "length": "10-20", "delay": 0}))
	require.NoError(t, err)
	_ = p.Close()

	p, err = ParseProxy(bpnVlessMapping(map[string]any{"packets": "1-3", "length": 50, "delay": "5-10", "max-split": 4}))
	require.NoError(t, err)
	_ = p.Close()

	// Unsupported or malformed fragment-opts warn and leave the proxy working
	// without fragmentation instead of breaking the whole subscription profile.
	for _, bad := range []any{
		map[string]any{"packets": "tlshello", "length": "0-5"},
		map[string]any{"packets": "first"},
		"not-a-map",
	} {
		parsed, err := ParseProxy(bpnVlessMapping(bad))
		require.NoError(t, err)
		wrapped := unwrapAutoClose(t, parsed.Adapter())
		vlessOut, ok := wrapped.(*outbound.Vless)
		require.True(t, ok)
		_ = vlessOut
		_ = parsed.Close()
	}

	// Direct Go construction with invalid fragment-opts also degrades cleanly.
	v, err := outbound.NewVless(outbound.VlessOption{
		BasicOption: outbound.BasicOption{FragmentOpts: fragment.Options{Packets: "first"}},
		Name:        "n", Server: "127.0.0.1", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555", TLS: true, ServerName: "example.com",
	})
	require.NoError(t, err)
	_ = v.Close()
}
