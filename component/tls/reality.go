package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

const RealityMaxShortIDLen = 8

// RealityClientVersion is the Xray-style "x.y.z" version that a REALITY client
// puts into the first three bytes of the session ID. Xray servers compare it
// with minClientVer/maxClientVer.
type RealityClientVersion [3]byte

// DefaultRealityClientVersion is reported when reality-opts.client-version is
// not set. It represents the tested REALITY compatibility, not Mihomo's
// application version.
//
// Xray-core REALITY servers compare this against minClientVer. Nodes on Xray
// >= 26.9.8 set minClientVer to 26.9.8 or newer (and such a server rejects a
// ClientHello without X25519MLKEM768 at all, XTLS/REALITY 8cdf7bf), so the old
// 26.3.27 default failed every handshake to a refreshed node. 26.10.21 is the
// newest release tested with this core; older servers do not set maxClientVer,
// so a newer version is accepted by them.
var DefaultRealityClientVersion = RealityClientVersion{26, 10, 21}

// ParseRealityClientVersion parses "x.y.z" (each part 0-255).
func ParseRealityClientVersion(s string) (RealityClientVersion, error) {
	var v RealityClientVersion
	parts := strings.Split(s, ".")
	if len(parts) != len(v) {
		return v, fmt.Errorf("invalid REALITY client version %q, want x.y.z", s)
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return v, fmt.Errorf("invalid REALITY client version %q, want x.y.z", s)
		}
		v[i] = byte(n)
	}
	return v, nil
}

type RealityConfig struct {
	PublicKey *ecdh.PublicKey
	ShortID   [RealityMaxShortIDLen]byte

	SupportX25519MLKEM768 bool

	// MLKEMFingerprint replaces the configured client fingerprint for a
	// handshake that offers X25519MLKEM768 (BadVPN P7). Russian mobile carriers
	// hold a Chrome ClientHello to a "suspicious" foreign subnet and pass
	// Firefox/Android/OkHttp/Edge (XTLS/Xray-core#6293), while only chrome,
	// firefox and safari fingerprints carry the ML-KEM key share. A node that
	// requires ML-KEM can therefore keep client-fingerprint: chrome for other
	// networks and set mlkem-client-fingerprint: firefox for these carriers.
	// Nil keeps the configured fingerprint.
	MLKEMFingerprint *UClientHelloID

	// ClientVersion is reported in the session ID; zero value means DefaultRealityClientVersion.
	ClientVersion RealityClientVersion
}

// realityFingerprint picks the ClientHello to send. With X25519MLKEM768 in the
// handshake an explicit mlkem-client-fingerprint wins; otherwise the configured
// fingerprint is used.
func realityFingerprint(useMLKEM bool, fingerprint UClientHelloID, config *RealityConfig) UClientHelloID {
	if useMLKEM && config.MLKEMFingerprint != nil {
		return *config.MLKEMFingerprint
	}
	return fingerprint
}

// BadVPN P6: adaptive X25519MLKEM768. Xray servers are split by generation:
// builds before 2025 drop a ClientHello with the hybrid key share, builds from
// 26.9.8 on (XTLS/REALITY 8cdf7bf) reject one without it, and a server never
// says which it is. Without support-x25519mlkem768 the outcome of each
// handshake is remembered per server address and public key: classic first
// (P4 behaviour), flip after one failure, pin after one success, flip a pinned
// verdict again after realityMemoFlipAfter failures in a row (servers get
// upgraded). A wrong guess costs one failed connection per server.
// Adapted from the ClashFest core patch 0002 (Nemu-x, GPL-3.0).
type realityMemoEntry struct {
	mlkem    bool
	pinned   bool
	failures int
	flips    int
}

const realityMemoFlipAfter = 3

var realityMemo = struct {
	sync.Mutex
	entries map[string]*realityMemoEntry
}{entries: map[string]*realityMemoEntry{}}

func realityMemoKey(conn net.Conn, config *RealityConfig) string {
	key := string(config.PublicKey.Bytes())
	if addr := conn.RemoteAddr(); addr != nil {
		key = addr.String() + "|" + key
	}
	return key
}

// realityChooseMLKEM returns whether this handshake offers X25519MLKEM768 and
// whether the choice came from the memo (and so must be reported back).
func realityChooseMLKEM(key string, config *RealityConfig) (mlkem bool, adaptive bool) {
	if config.SupportX25519MLKEM768 {
		return true, false
	}
	realityMemo.Lock()
	defer realityMemo.Unlock()
	if entry, ok := realityMemo.entries[key]; ok {
		return entry.mlkem, true
	}
	return false, true
}

func realityReportMLKEM(key string, mlkem bool, ok bool, remote net.Addr) {
	realityMemo.Lock()
	defer realityMemo.Unlock()
	entry := realityMemo.entries[key]
	if entry == nil {
		entry = &realityMemoEntry{mlkem: mlkem}
		realityMemo.entries[key] = entry
	}
	if ok {
		if !entry.pinned || entry.mlkem != mlkem {
			log.Infoln("REALITY %v: X25519MLKEM768=%v confirmed", remote, mlkem)
		}
		entry.mlkem, entry.pinned, entry.failures, entry.flips = mlkem, true, 0, 0
		return
	}
	if entry.mlkem != mlkem {
		return // a stale attempt; the memo already moved on
	}
	entry.failures++
	if !entry.pinned || entry.failures >= realityMemoFlipAfter {
		entry.mlkem, entry.pinned, entry.failures = !mlkem, false, 0
		entry.flips++
		// A server that rejects both is down or misconfigured: keep flipping
		// (it may come back) but stop narrating it after two rounds.
		if entry.flips <= 2 {
			log.Infoln("REALITY %v: handshake with X25519MLKEM768=%v failed, next attempt uses %v", remote, mlkem, !mlkem)
		} else {
			log.Debugln("REALITY %v: handshake with X25519MLKEM768=%v failed again, next attempt uses %v", remote, mlkem, !mlkem)
		}
	}
}

func realityHasMLKEMShare(uConn *utls.UConn) bool {
	keys := uConn.HandshakeState.State13.KeyShareKeys
	return keys != nil && keys.MlkemEcdhe != nil
}

// ResetRealityMLKEMMemo forgets every learned verdict (tests).
func ResetRealityMLKEMMemo() {
	realityMemo.Lock()
	defer realityMemo.Unlock()
	realityMemo.entries = map[string]*realityMemoEntry{}
}

func GetRealityConn(ctx context.Context, conn net.Conn, fingerprint UClientHelloID, serverName string, realityConfig *RealityConfig) (net.Conn, error) {
	memoKey := realityMemoKey(conn, realityConfig)
	useMLKEM, adaptive := realityChooseMLKEM(memoKey, realityConfig)
	report := func(ok bool) {
		if adaptive {
			realityReportMLKEM(memoKey, useMLKEM, ok, conn.RemoteAddr())
		}
	}
	// Pick the ML-KEM fingerprint once, before the retry loop: the loop below
	// substitutes chrome for a fingerprint without the hybrid key share and
	// retries, and applying the configured ML-KEM fingerprint on every
	// iteration would undo that and loop forever.
	fingerprint = realityFingerprint(useMLKEM, fingerprint, realityConfig)
	for retry := 0; ; retry++ {
		verifier := &realityVerifier{
			serverName: serverName,
		}
		uConfig := &utls.Config{
			Time:                   ntp.Now,
			ServerName:             serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyConnection:       verifier.VerifyConnection,
		}

		uConn := utls.UClient(conn, uConfig, fingerprint)
		verifier.UConn = uConn
		err := uConn.BuildHandshakeState()
		if err != nil {
			return nil, err
		}

		// P6: the memo wants the hybrid share but this fingerprint has none
		// (edge, ios, android, chrome120...): chrome is the only hello that can
		// still reach that server. An explicit support-x25519mlkem768 keeps the
		// configured fingerprint, as before.
		if useMLKEM && adaptive && !realityHasMLKEMShare(uConn) && fingerprint.Client != utls.HelloChrome_Auto.Client {
			log.Debugln("REALITY %v: %s fingerprint has no X25519MLKEM768 key share, using chrome", conn.RemoteAddr(), fingerprint.Client)
			fingerprint = utls.HelloChrome_Auto
			continue
		}

		if !useMLKEM { // BadVPN P4/P6: see adapter/outbound/reality.go
			err = BuildRemovedX25519MLKEM768HandshakeState(uConn)
			if err != nil {
				return nil, err
			}
		}

		hello := uConn.HandshakeState.Hello
		rawSessionID := hello.Raw[39 : 39+32] // the location of session ID
		for i := range rawSessionID {         // https://github.com/golang/go/issues/5373
			rawSessionID[i] = 0
		}

		binary.BigEndian.PutUint64(hello.SessionId, uint64(ntp.Now().Unix()))

		copy(hello.SessionId[8:], realityConfig.ShortID[:])
		clientVersion := realityConfig.ClientVersion
		if clientVersion == (RealityClientVersion{}) {
			clientVersion = DefaultRealityClientVersion
		}
		copy(hello.SessionId[:3], clientVersion[:])

		//log.Debugln("REALITY hello.sessionId[:16]: %v", hello.SessionId[:16])

		keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
		if keyShareKeys == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil keyShareKeys")
			}
			continue // retry
		}
		ecdheKey := keyShareKeys.Ecdhe
		if ecdheKey == nil {
			ecdheKey = keyShareKeys.MlkemEcdhe
		}
		if ecdheKey == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil ecdheKey")
			}
			continue // retry
		}
		authKey, err := ecdheKey.ECDH(realityConfig.PublicKey)
		if err != nil {
			return nil, err
		}
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		aesBlock, _ := aes.NewCipher(authKey)
		aeadCipher, _ := cipher.NewGCM(aesBlock)
		aeadCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
		//log.Debugln("REALITY hello.sessionId: %v", hello.SessionId)
		//log.Debugln("REALITY uConn.AuthKey: %v", authKey)

		err = uConn.HandshakeContext(ctx)
		if err != nil {
			report(false)
			return nil, err
		}

		log.Debugln("REALITY Authentication: %v, AEAD: %T", verifier.verified, aeadCipher)

		if !verifier.verified {
			report(false)
			go realityClientFallback(uConn, uConfig.ServerName, fingerprint)
			return nil, errors.New("REALITY authentication failed")
		}

		report(true)
		return uConn, nil
	}
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			Protocols: protocols,
		},
	}
	request, err := http.NewRequest("GET", "https://"+serverName, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", randv2.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	//_, _ = io.Copy(io.Discard, response.Body)
	time.Sleep(time.Duration(5+randv2.IntN(10)) * time.Second)
	response.Body.Close()
	client.CloseIdleConnections()
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyConnection(state utls.ConnectionState) error {
	log.Debugln("REALITY localAddr: %v is using X25519MLKEM768 for TLS' communication: %v", c.RemoteAddr(), c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
	certs := state.PeerCertificates
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   ntp.Now(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}
