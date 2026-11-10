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

func TestBPNRealityOptionsMLKEMClientFingerprint(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	config, err := RealityOptions{PublicKey: publicKey}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if config.MLKEMFingerprint != nil {
		t.Fatal("unset mlkem-client-fingerprint set a fingerprint")
	}

	config, err = RealityOptions{PublicKey: publicKey, MLKEMClientFingerprint: "firefox"}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := tlsC.GetFingerprint("firefox")
	if config.MLKEMFingerprint == nil || config.MLKEMFingerprint.Client != want.Client || config.MLKEMFingerprint.Version != want.Version {
		t.Fatalf("mlkem-client-fingerprint = %v, want firefox", config.MLKEMFingerprint)
	}

	if _, err = (RealityOptions{PublicKey: publicKey, MLKEMClientFingerprint: "no-such-browser"}).Parse(); err == nil {
		t.Fatal("invalid mlkem-client-fingerprint accepted")
	}

	// edge has no X25519MLKEM768 key share: a handshake that must offer
	// ML-KEM could only fall back to chrome or lose the server, so reject it
	// at parse time instead of looping on the substitution.
	if _, err = (RealityOptions{PublicKey: publicKey, MLKEMClientFingerprint: "edge"}).Parse(); err == nil {
		t.Fatal("mlkem-client-fingerprint without X25519MLKEM768 accepted")
	}
}

func TestBPNRealityMLKEMFingerprintRandom(t *testing.T) {
	ios, _ := tlsC.GetFingerprint("ios")
	if tlsC.FingerprintSupportsX25519MLKEM768(ios) {
		t.Skip("ios got an X25519MLKEM768 key share, nothing to substitute")
	}

	// "random" landed on ios: chrome instead of a config error.
	got, err := realityMLKEMFingerprint("random", ios)
	if err != nil {
		t.Fatalf("random -> ios rejected: %v", err)
	}
	if got.Client != tlsC.HelloChromeAuto.Client || got.Version != tlsC.HelloChromeAuto.Version {
		t.Fatalf("random -> ios gave %v, want chrome", got)
	}

	// "random" landed on a fingerprint with ML-KEM: kept as is.
	firefox, _ := tlsC.GetFingerprint("firefox")
	got, err = realityMLKEMFingerprint("random", firefox)
	if err != nil || got.Client != firefox.Client || got.Version != firefox.Version {
		t.Fatalf("random -> firefox gave %v, %v", got, err)
	}

	// A named fingerprint without ML-KEM stays an error.
	if _, err = realityMLKEMFingerprint("ios", ios); err == nil {
		t.Fatal("named ios without X25519MLKEM768 accepted")
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	config, err := RealityOptions{PublicKey: publicKey, MLKEMClientFingerprint: "random"}.Parse()
	if err != nil {
		t.Fatalf("mlkem-client-fingerprint random: %v", err)
	}
	if config.MLKEMFingerprint == nil || !tlsC.FingerprintSupportsX25519MLKEM768(*config.MLKEMFingerprint) {
		t.Fatalf("mlkem-client-fingerprint random gave %v without X25519MLKEM768", config.MLKEMFingerprint)
	}
}

func TestBPNRealityOptionsSupportX25519MLKEM768(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	for _, want := range []bool{false, true} {
		config, err := RealityOptions{PublicKey: publicKey, SupportX25519MLKEM768: want}.Parse()
		if err != nil {
			t.Fatal(err)
		}
		if config.SupportX25519MLKEM768 != want {
			t.Fatalf("support-x25519mlkem768 = %v, want %v", config.SupportX25519MLKEM768, want)
		}
	}
}
