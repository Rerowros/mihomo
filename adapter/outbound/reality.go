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

	// BadVPN P4/P6: true always offers X25519MLKEM768. Without it the first
	// handshake to a server is classic (P4: real Xray 26.3.27 nodes failed with
	// ML-KEM in the field, BADVPN.md) and the core learns per server whether it
	// needs ML-KEM (Xray >= 26.9.8) from the handshake outcome (P6).
	SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`

	// MLKEMClientFingerprint (BadVPN P7) replaces client-fingerprint for a
	// handshake that offers X25519MLKEM768. Russian mobile carriers hold a
	// Chrome ClientHello to a suspicious foreign subnet and pass Firefox/
	// Android/OkHttp/Edge (XTLS/Xray-core#6293); firefox is the passing
	// fingerprint that also carries the ML-KEM key share.
	MLKEMClientFingerprint string `proxy:"mlkem-client-fingerprint,omitempty"`

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

		if o.MLKEMClientFingerprint != "" {
			fingerprint, ok := tlsC.GetFingerprint(o.MLKEMClientFingerprint)
			if !ok {
				return nil, fmt.Errorf("invalid mlkem-client-fingerprint %q", o.MLKEMClientFingerprint)
			}
			if !tlsC.FingerprintSupportsX25519MLKEM768(fingerprint) {
				return nil, fmt.Errorf("mlkem-client-fingerprint %q has no X25519MLKEM768 key share", o.MLKEMClientFingerprint)
			}
			config.MLKEMFingerprint = &fingerprint
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
