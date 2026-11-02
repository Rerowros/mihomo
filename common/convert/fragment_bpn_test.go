package convert

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBPNConvertsVlessFinalMaskFragment(t *testing.T) {
	fm := `{"tcp":[{"type":"header-custom","settings":{}},{"type":"fragment","settings":{"packets":"tlshello","length":"10-20","delay":0,"maxSplit":"5-9"}}]}`
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:2053?security=reality&pbk=key&sid=ab&sni=example.ru&fp=chrome&type=tcp&fm=" + url.QueryEscape(fm) + "#n"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	require.Equal(t, map[string]any{"packets": "tlshello", "length": "10-20", "delay": "0", "max-split": "5-9"}, proxies[0]["fragment-opts"])

	for _, fm := range []string{"", "not json", `{"tcp":[{"type":"header-custom"}]}`, `{"udp":[{"type":"fragment"}]}`,
		`{"tcp":[{"type":"fragment","settings":{"packets":"abc"}}]}`, `{"tcp":[{"type":"fragment","settings":{"delay":-1}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"delay":"0-9223372036854775807"}}]}`} {
		link := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&fm=" + url.QueryEscape(fm) + "#n"
		proxies, err := ConvertsV2Ray([]byte(link))
		require.NoError(t, err)
		require.NotContains(t, proxies[0], "fragment-opts", "fm=%q", fm)
	}

	fm = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["10-20","30"],"delays":[0]}}]}`
	link = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&fm=" + url.QueryEscape(fm) + "#n"
	proxies, err = ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Equal(t, map[string]any{"packets": "tlshello", "length": "10-20", "delay": "0"}, proxies[0]["fragment-opts"])
}
