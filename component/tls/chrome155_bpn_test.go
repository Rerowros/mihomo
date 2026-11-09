package tls

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	utls "github.com/metacubex/utls"
)

// BadVPN P20 (see BADVPN.md): "chrome" sends the Chrome 155 ClientHello.
// testdata/chrome155_clienthello.hex is the first TLS record of a fresh
// connection of Google Chrome 155.0.8059.40 to www.example.com, taken from
// refraction-networking/utls 6ebdceb2 (testdata/chrome155_clienthello.md
// there; SHA-256 of the handshake 235618e3...439a).

type parsedClientHello struct {
	version      uint16
	sessionIDLen int
	cipherSuites []uint16
	compression  []byte
	extensionIDs []uint16          // wire order
	extensions   map[uint16][]byte // extension_data by type
}

func isGREASE(v uint16) bool {
	return v>>8 == v&0xff && v&0xf == 0xa
}

// parseClientHello reads a ClientHello handshake message (with its four-byte
// header) and replaces every GREASE extension type with 0x0a0a.
func parseClientHello(t *testing.T, raw []byte) parsedClientHello {
	t.Helper()
	if len(raw) < 4 || raw[0] != 1 || int(raw[1])<<16|int(raw[2])<<8|int(raw[3]) != len(raw)-4 {
		t.Fatalf("not a ClientHello handshake message, %d bytes", len(raw))
	}
	b := raw[4:]
	next := func(n int) []byte {
		t.Helper()
		if len(b) < n {
			t.Fatalf("ClientHello truncated")
		}
		out := b[:n]
		b = b[n:]
		return out
	}
	var hello parsedClientHello
	hello.version = binary.BigEndian.Uint16(next(2))
	next(32) // random
	hello.sessionIDLen = len(next(int(next(1)[0])))
	suites := next(int(binary.BigEndian.Uint16(next(2))))
	for i := 0; i+1 < len(suites); i += 2 {
		hello.cipherSuites = append(hello.cipherSuites, binary.BigEndian.Uint16(suites[i:]))
	}
	hello.compression = next(int(next(1)[0]))
	if extLen := int(binary.BigEndian.Uint16(next(2))); extLen != len(b) {
		t.Fatalf("extensions length %d, %d bytes left", extLen, len(b))
	}
	hello.extensions = map[uint16][]byte{}
	for len(b) > 0 {
		id := binary.BigEndian.Uint16(next(2))
		data := next(int(binary.BigEndian.Uint16(next(2))))
		if isGREASE(id) {
			id = 0x0a0a
		}
		hello.extensionIDs = append(hello.extensionIDs, id)
		hello.extensions[id] = data
	}
	return hello
}

// ungrease replaces GREASE values in a list of uint16 that starts at offset.
func ungrease(data []byte, offset int) []byte {
	out := bytes.Clone(data)
	for i := offset; i+1 < len(out); i += 2 {
		if isGREASE(binary.BigEndian.Uint16(out[i:])) {
			out[i], out[i+1] = 0x0a, 0x0a
		}
	}
	return out
}

// keyShareShape returns "group:length" of every key share, GREASE as 0a0a.
func keyShareShape(t *testing.T, data []byte) []string {
	t.Helper()
	var out []string
	for b := data[2:]; len(b) > 0; {
		if len(b) < 4 {
			t.Fatalf("key_share truncated")
		}
		group, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if isGREASE(group) {
			group = 0x0a0a
		}
		out = append(out, hex.EncodeToString([]byte{byte(group >> 8), byte(group)})+":"+hex.EncodeToString([]byte{byte(n >> 8), byte(n)}))
		b = b[4+n:]
	}
	return out
}

func buildRawClientHello(t *testing.T, name string, serverName string) []byte {
	t.Helper()
	id, ok := GetFingerprint(name)
	if !ok {
		t.Fatalf("fingerprint %q not found", name)
	}
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	uConn := UClient(client, &utls.Config{ServerName: serverName}, id)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState(%s): %v", name, err)
	}
	return uConn.HandshakeState.Hello.Raw
}

func TestBPNChrome155MatchesBrowserCapture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/chrome155_clienthello.hex")
	if err != nil {
		t.Fatal(err)
	}
	record, err := hex.DecodeString(strings.TrimSpace(string(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	want := parseClientHello(t, record[5:]) // skip the TLS record header

	const (
		extSupportedGroups = 10
		extSigAlgs         = 13
		extSupportedVers   = 43
		extKeyShare        = 51
		extECH             = 0xfe0d
	)

	for _, name := range []string{"chrome", "chrome155"} {
		t.Run(name, func(t *testing.T) {
			// Extension order and GREASE values are random: several hellos.
			for i := 0; i < 20; i++ {
				raw := buildRawClientHello(t, name, "www.example.com")
				got := parseClientHello(t, raw)

				if got.version != want.version || got.sessionIDLen != want.sessionIDLen {
					t.Fatalf("version %04x, session ID %d bytes; Chrome sends %04x and %d", got.version, got.sessionIDLen, want.version, want.sessionIDLen)
				}
				if g, w := ungreaseSuites(got.cipherSuites), ungreaseSuites(want.cipherSuites); !slices.Equal(g, w) {
					t.Fatalf("cipher suites %04x, Chrome sends %04x", g, w)
				}
				if !isGREASE(got.cipherSuites[0]) {
					t.Fatalf("first cipher suite %04x is not GREASE", got.cipherSuites[0])
				}
				if !bytes.Equal(got.compression, want.compression) {
					t.Fatalf("compression %x, Chrome sends %x", got.compression, want.compression)
				}

				// Chrome shuffles everything between the two GREASE extensions.
				n := len(got.extensionIDs)
				if n != len(want.extensionIDs) || got.extensionIDs[0] != 0x0a0a || got.extensionIDs[n-1] != 0x0a0a {
					t.Fatalf("extensions %04x, Chrome sends %04x", got.extensionIDs, want.extensionIDs)
				}
				gotIDs, wantIDs := slices.Sorted(slices.Values(got.extensionIDs)), slices.Sorted(slices.Values(want.extensionIDs))
				if !slices.Equal(gotIDs, wantIDs) {
					t.Fatalf("extension set %04x, Chrome sends %04x", gotIDs, wantIDs)
				}

				for _, id := range wantIDs {
					g, w := got.extensions[id], want.extensions[id]
					switch id {
					case 0x0a0a: // two GREASE extensions with different bodies; checked by length below
						continue
					case extSupportedGroups, extSigAlgs:
						g, w = ungrease(g, 2), ungrease(w, 2)
					case extSupportedVers:
						g, w = ungrease(g, 1), ungrease(w, 1)
					case extKeyShare:
						if gs, ws := keyShareShape(t, g), keyShareShape(t, w); !slices.Equal(gs, ws) {
							t.Fatalf("key shares %v, Chrome sends %v", gs, ws)
						}
						continue
					case extECH:
						// GREASE ECH: random key and payload; BoringSSL picks the
						// payload from 144/176/208/240 bytes, the capture has 176.
						if d := len(g) - len(w); d != -32 && d != 0 && d != 32 && d != 64 {
							t.Fatalf("GREASE ECH is %d bytes, Chrome sends %d (+-32n)", len(g), len(w))
						}
						if !bytes.Equal(g[:5], w[:5]) { // type, KDF, AEAD; the config id after them is random
							t.Fatalf("GREASE ECH header %x, Chrome sends %x", g[:5], w[:5])
						}
						continue
					}
					if !bytes.Equal(g, w) {
						t.Fatalf("extension %04x = %x, Chrome sends %x", id, g, w)
					}
				}

				// signature_algorithms must start with a GREASE value: utls of
				// this fork does not fill it in, chrome155Spec does.
				if sig := got.extensions[extSigAlgs]; !isGREASE(binary.BigEndian.Uint16(sig[2:])) {
					t.Fatalf("signature_algorithms starts with %x, want GREASE", sig[2:4])
				}

				// Same size as the browser's hello, up to the GREASE ECH payload.
				if d := len(raw) - (len(record) - 5); d != -32 && d != 0 && d != 32 && d != 64 {
					t.Fatalf("ClientHello is %d bytes, Chrome sends %d (+-32n)", len(raw), len(record)-5)
				}
			}
		})
	}
}

func ungreaseSuites(suites []uint16) []uint16 {
	out := slices.Clone(suites)
	for i, suite := range out {
		if isGREASE(suite) {
			out[i] = 0x0a0a
		}
	}
	return out
}

// The profile used before P20 stays reachable, and it is not the new one.
func TestBPNChrome133StillAvailable(t *testing.T) {
	old := parseClientHello(t, buildRawClientHello(t, "chrome133", "www.example.com"))
	if _, ok := old.extensions[extensionTrustAnchors]; ok {
		t.Fatal("chrome133 sends trust_anchors: it must stay the Chrome 133 hello")
	}
	if id, _ := GetFingerprint("chrome133"); id != utls.HelloChrome_133 {
		t.Fatalf("chrome133 = %v", id)
	}
}

func TestBPNChrome155SupportsMLKEM(t *testing.T) {
	if !FingerprintSupportsX25519MLKEM768(HelloChrome155) {
		t.Fatal("Chrome 155 carries an X25519MLKEM768 key share")
	}
}
