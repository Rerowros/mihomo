package adapter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func bpnVlessMapping(fragmentOpts map[string]any) map[string]any {
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
	_, err := ParseProxy(bpnVlessMapping(nil))
	require.NoError(t, err)
	// YAML numbers are accepted where Xray accepts them
	_, err = ParseProxy(bpnVlessMapping(map[string]any{"packets": "tlshello", "length": "10-20", "delay": 0}))
	require.NoError(t, err)
	_, err = ParseProxy(bpnVlessMapping(map[string]any{"packets": "1-3", "length": 50, "delay": "5-10", "max-split": 4}))
	require.NoError(t, err)

	_, err = ParseProxy(bpnVlessMapping(map[string]any{"packets": "tlshello", "length": "0-5"}))
	require.ErrorContains(t, err, "fragment-opts.length")
	_, err = ParseProxy(bpnVlessMapping(map[string]any{"packets": "first"}))
	require.ErrorContains(t, err, "fragment-opts.packets")
}
