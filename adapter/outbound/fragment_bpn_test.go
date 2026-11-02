package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/component/fragment"

	"github.com/stretchr/testify/require"
)

// fragment-opts wraps the dialer of every proxy type built on BasicOption.NewDialer
func TestBPNFragmentOptsWrapsDialer(t *testing.T) {
	newVless := func(opts fragment.Options) *Vless {
		v, err := NewVless(VlessOption{
			BasicOption: BasicOption{FragmentOpts: opts},
			Name:        "n", Server: "127.0.0.1", Port: 443,
			UUID: "11111111-2222-3333-4444-555555555555", TLS: true, ServerName: "example.com",
		})
		require.NoError(t, err)
		return v
	}
	_, wrapped := newVless(fragment.Options{}).dialer.(fragment.Dialer)
	require.False(t, wrapped, "off by default")
	_, wrapped = newVless(fragment.Options{Packets: "tlshello", Length: "10-20", Delay: "0"}).dialer.(fragment.Dialer)
	require.True(t, wrapped)

	tr, err := NewTrojan(TrojanOption{
		BasicOption: BasicOption{FragmentOpts: fragment.Options{Packets: "tlshello"}},
		Name:        "t", Server: "127.0.0.1", Port: 443, Password: "p", SNI: "example.com",
	})
	require.NoError(t, err)
	_, wrapped = tr.dialer.(fragment.Dialer)
	require.True(t, wrapped)
}
