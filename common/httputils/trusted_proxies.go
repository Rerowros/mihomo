package httputils

import (
	"fmt"
	"net/netip"
	"strings"
)

var trustedProxyShorthands = map[string][]netip.Prefix{
	"loopback": {
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	},
	"private": {
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	},
}

// ParseTrustedProxies parses a trusted-proxies list: CIDRs, single addresses
// and the shorthands "loopback" (127.0.0.0/8, ::1) and "private" (10.0.0.0/8,
// 172.16.0.0/12, 192.168.0.0/16, fc00::/7).
func ParseTrustedProxies(list []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if shorthand, ok := trustedProxyShorthands[strings.ToLower(item)]; ok {
			prefixes = append(prefixes, shorthand...)
			continue
		}
		if strings.Contains(item, "/") {
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", item, err)
			}
			if prefix.Addr().Is4In6() {
				bits := prefix.Bits() - 96
				if bits < 0 {
					return nil, fmt.Errorf("invalid trusted proxy %q: an IPv4-mapped prefix shorter than /96", item)
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", item, err)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}
