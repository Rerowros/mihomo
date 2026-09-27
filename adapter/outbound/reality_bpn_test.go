package outbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

func TestBPNRealityOptionsClientVersion(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	config, err := RealityOptions{PublicKey: publicKey}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientVersion != (tlsC.RealityClientVersion{}) {
		t.Fatalf("unset client-version = %v, want zero (use default)", config.ClientVersion)
	}

	config, err = RealityOptions{PublicKey: publicKey, ClientVersion: "26.9.9"}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientVersion != (tlsC.RealityClientVersion{26, 9, 9}) {
		t.Fatalf("client-version = %v, want 26.9.9", config.ClientVersion)
	}

	if _, err = (RealityOptions{PublicKey: publicKey, ClientVersion: "26.9"}).Parse(); err == nil {
		t.Fatal("invalid client-version accepted")
	}
}
