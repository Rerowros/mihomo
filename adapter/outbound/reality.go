package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey string `proxy:"public-key"`
	ShortID   string `proxy:"short-id,omitempty"`

	// BadVPN P4: X25519MLKEM768 is stripped from the ClientHello unless this is
	// true (upstream semantics). Real Xray 26.3.27 nodes with targets without
	// ML-KEM failed with it in the field (BADVPN.md, P4). Xray >= 26.9.8 nodes
	// need true.
	SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`

	// ClientVersion overrides the "x.y.z" version reported to the server
	// (default tlsC.DefaultRealityClientVersion).
	ClientVersion string `proxy:"client-version,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		if o.ClientVersion != "" {
			config.ClientVersion, err = tlsC.ParseRealityClientVersion(o.ClientVersion)
			if err != nil {
				return nil, err
			}
		}

		return config, nil
	}
	return nil, nil
}
