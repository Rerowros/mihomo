package listener

import (
	"testing"

	IN "github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseListener_ProxyProtocol(t *testing.T) {
	l, err := ParseListener(map[string]any{
		"name":                   "vless-in",
		"type":                   "vless",
		"listen":                 "127.0.0.1",
		"port":                   "0",
		"proxy-protocol":         true,
		"proxy-protocol-trusted": []any{"loopback", "10.0.0.0/8"},
		"users":                  []any{map[string]any{"uuid": "00000000-0000-0000-0000-000000000000"}},
		"allow-insecure":         true,
		"ws-path":                "/ws",
		"fallback-page":          "page.html",
	})
	require.NoError(t, err)
	config, ok := l.Config().(*IN.VlessOption)
	require.True(t, ok)
	assert.True(t, config.ProxyProtocol)
	assert.Equal(t, []string{"loopback", "10.0.0.0/8"}, config.ProxyProtocolTrusted)
	assert.Equal(t, "page.html", config.FallbackPage)

	// a listener without TCP streams cannot carry it
	_, err = ParseListener(map[string]any{"name": "redir-in", "type": "redir", "listen": "127.0.0.1", "port": "0", "proxy-protocol": true})
	assert.ErrorContains(t, err, "proxy-protocol")
}
