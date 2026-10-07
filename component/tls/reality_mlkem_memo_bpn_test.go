package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"slices"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

// BadVPN P6 (BADVPN.md): without support-x25519mlkem768 the REALITY client
// learns per server and public key whether the server needs X25519MLKEM768.
// Based on the ClashFest core patch 0002 tests (Nemu-x, GPL-3.0).

type bpnFakeAddr string

func (a bpnFakeAddr) Network() string { return "tcp" }
func (a bpnFakeAddr) String() string  { return string(a) }

func bpnMemoConfig(t *testing.T, force bool) *RealityConfig {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &RealityConfig{PublicKey: key.PublicKey(), SupportX25519MLKEM768: force}
}

func TestBPNRealityMLKEMMemoLearnsPerServer(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	config := bpnMemoConfig(t, false)
	addr := net.Addr(bpnFakeAddr("203.0.113.1:443"))
	key := addr.String() + "|" + string(config.PublicKey.Bytes())

	if mlkem, adaptive := realityChooseMLKEM(key, config); mlkem || !adaptive {
		t.Fatalf("first guess = (%v, %v), want classic and adaptive (P4 default)", mlkem, adaptive)
	}
	realityReportMLKEM(key, false, false, addr) // Xray >= 26.9.8 rejected the classic hello
	if mlkem, _ := realityChooseMLKEM(key, config); !mlkem {
		t.Fatal("memo did not flip to X25519MLKEM768 after a classic failure")
	}
	realityReportMLKEM(key, false, false, addr) // a stale classic attempt that was in flight
	if mlkem, _ := realityChooseMLKEM(key, config); !mlkem {
		t.Fatal("a stale classic failure flipped the memo back")
	}
	realityReportMLKEM(key, true, true, addr)
	for i := 0; i < realityMemoFlipAfter-1; i++ {
		realityReportMLKEM(key, true, false, addr) // network blips must not unpin a confirmed verdict
	}
	if mlkem, _ := realityChooseMLKEM(key, config); !mlkem {
		t.Fatal("pinned verdict was dropped by transient failures")
	}
	realityReportMLKEM(key, true, false, addr)
	if mlkem, _ := realityChooseMLKEM(key, config); mlkem {
		t.Fatal("verdict did not flip after repeated failures (server changed)")
	}

	other := addr.String() + "|" + string(bpnMemoConfig(t, false).PublicKey.Bytes())
	if mlkem, _ := realityChooseMLKEM(other, config); mlkem {
		t.Fatal("memo leaked between public keys")
	}
	otherAddr := "203.0.113.2:443|" + string(config.PublicKey.Bytes())
	if mlkem, _ := realityChooseMLKEM(otherAddr, config); mlkem {
		t.Fatal("memo leaked between servers")
	}
}

func TestBPNRealityMLKEMForcedSkipsMemo(t *testing.T) {
	ResetRealityMLKEMMemo()
	t.Cleanup(ResetRealityMLKEMMemo)
	config := bpnMemoConfig(t, true)
	if mlkem, adaptive := realityChooseMLKEM("198.51.100.1:443|x", config); !mlkem || adaptive {
		t.Fatalf("support-x25519mlkem768 = (%v, %v), want forced hybrid outside the memo", mlkem, adaptive)
	}
}

// A learned "needs ML-KEM" verdict must reach the wire: for a fingerprint with
// the share (firefox) the hello keeps it; for one without it (edge) the hello
// is swapped for chrome, the only one that can pass such a server.
func TestBPNRealityMLKEMMemoReachesClientHello(t *testing.T) {
	for _, name := range []string{"firefox", "edge"} {
		t.Run(name, func(t *testing.T) {
			ResetRealityMLKEMMemo()
			t.Cleanup(ResetRealityMLKEMMemo)
			id, _ := GetFingerprint(name)
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			config := &RealityConfig{PublicKey: privateKey.PublicKey()}

			capture := func() *utls.PubClientHelloMsg {
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				deadline := time.Now().Add(5 * time.Second)
				_ = client.SetDeadline(deadline)
				_ = server.SetDeadline(deadline)
				done := make(chan struct{})
				go func() {
					defer close(done)
					_, _ = GetRealityConn(context.Background(), client, id, "example.com", config)
				}()
				hello, err := readClientHello(server)
				if err != nil || hello == nil {
					t.Fatalf("capture ClientHello: %v", err)
				}
				_ = server.Close()
				<-done
				return hello
			}

			// First attempt: classic. The capture closes the connection, which
			// counts as a failure, so the next attempt must carry ML-KEM.
			if hello := capture(); slices.Contains(keyShareGroups(hello), utls.X25519MLKEM768) {
				t.Fatalf("first ClientHello has X25519MLKEM768: %v", keyShareGroups(hello))
			}
			hello := capture()
			t.Logf("%s second ClientHello: %d bytes, key shares %v", name, len(hello.Raw), keyShareGroups(hello))
			if !xrayAcceptsKeyShares(hello.KeyShares) {
				t.Fatalf("second ClientHello lacks X25519MLKEM768 before X25519: %v", keyShareGroups(hello))
			}
		})
	}
}
