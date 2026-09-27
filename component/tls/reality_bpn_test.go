package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

// BadVPN patch set (see BADVPN.md): REALITY must report the Xray-style client
// version 26.3.27 and keep the fingerprint's X25519MLKEM768 key share, placed
// before X25519, as Xray >= 26.9.8 (XTLS/REALITY 8cdf7bf) requires.

func TestBPNFingerprintVersions(t *testing.T) {
	// Guards against Go MVS silently resolving metacubex/utls back to v1.8.7
	// (Firefox 120 / Safari 16) in a consumer module.
	for name, want := range map[string]string{
		"chrome":  "133",
		"firefox": "148",
		"safari":  "26.3",
		"edge":    "85",
	} {
		id, ok := GetFingerprint(name)
		if !ok {
			t.Fatalf("fingerprint %q not found", name)
		}
		if id.Version != want {
			t.Errorf("fingerprint %q = %s %s, want version %s", name, id.Client, id.Version, want)
		}
	}
}

func TestBPNRealityDefaultClientVersion(t *testing.T) {
	for _, name := range []string{"chrome", "firefox", "safari", "edge"} {
		t.Run(name, func(t *testing.T) {
			id, _ := GetFingerprint(name)
			hello, privateKey := captureRealityClientHello(t, id)
			plain := decryptRealitySessionID(t, hello, privateKey)
			if got, want := [3]byte(plain[:3]), [3]byte{26, 3, 27}; got != want {
				t.Fatalf("REALITY client version = %v, want %v", got, want)
			}
			if plain[3] != 0 {
				t.Fatalf("REALITY reserved byte = %d, want 0", plain[3])
			}
		})
	}
}

func TestBPNRealityClientVersionOverride(t *testing.T) {
	id, _ := GetFingerprint("firefox")
	hello, privateKey := captureRealityClientHelloWithConfig(t, id, RealityClientVersion{1, 8, 2})
	plain := decryptRealitySessionID(t, hello, privateKey)
	if got, want := [3]byte(plain[:3]), [3]byte{1, 8, 2}; got != want {
		t.Fatalf("REALITY client version = %v, want %v", got, want)
	}
}

func TestBPNParseRealityClientVersion(t *testing.T) {
	v, err := ParseRealityClientVersion("26.9.9")
	if err != nil || v != (RealityClientVersion{26, 9, 9}) {
		t.Fatalf("ParseRealityClientVersion(26.9.9) = %v, %v", v, err)
	}
	for _, bad := range []string{"", "26.3", "26.3.27.1", "26.3.x", "256.0.0", "-1.0.0"} {
		if _, err := ParseRealityClientVersion(bad); err == nil {
			t.Errorf("ParseRealityClientVersion(%q) succeeded, want error", bad)
		}
	}
}

// xrayAcceptsKeyShares mirrors the key share walk of XTLS/REALITY 8cdf7bf
// (Xray >= 26.9.8): X25519MLKEM768 must be present and come before X25519.
func xrayAcceptsKeyShares(keyShares []utls.KeyShare) bool {
	var hasMLKEM bool
	for _, keyShare := range keyShares {
		if keyShare.Group == utls.X25519MLKEM768 {
			if hasMLKEM {
				return false
			}
			hasMLKEM = true
			continue
		}
		if keyShare.Group == utls.X25519 {
			break
		}
	}
	return hasMLKEM
}

func TestBPNRealityKeepsMLKEMKeyShare(t *testing.T) {
	for name, want := range map[string]bool{
		"chrome":  true,
		"firefox": true,
		"safari":  true,
		// Edge 85 has no ML-KEM at all: Xray >= 26.9.8 rejects it for any client.
		"edge":       false,
		"chrome120":  false,
		"firefox120": false,
	} {
		t.Run(name, func(t *testing.T) {
			id, _ := GetFingerprint(name)
			hello, _ := captureRealityClientHello(t, id)
			groups := make([]utls.CurveID, 0, len(hello.KeyShares))
			for _, ks := range hello.KeyShares {
				groups = append(groups, ks.Group)
			}
			t.Logf("%s %s key shares: %v", id.Client, id.Version, groups)
			if got := xrayAcceptsKeyShares(hello.KeyShares); got != want {
				t.Fatalf("ML-KEM before X25519 = %v, want %v (key shares %v)", got, want, groups)
			}
		})
	}
}

func captureRealityClientHelloWithConfig(t *testing.T, fingerprint utls.ClientHelloID, clientVersion RealityClientVersion) (*utls.PubClientHelloMsg, *ecdh.PrivateKey) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	result := make(chan error, 1)
	go func() {
		_, err := GetRealityConn(context.Background(), client, fingerprint, "example.com", &RealityConfig{
			PublicKey:     privateKey.PublicKey(),
			ClientVersion: clientVersion,
		})
		result <- err
	}()

	hello, err := readClientHello(server)
	if err != nil || hello == nil {
		t.Fatalf("capture ClientHello: %v", err)
	}
	_ = server.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("REALITY client did not stop after capture connection closed")
	}
	return hello, privateKey
}
