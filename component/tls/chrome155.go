package tls

import (
	randv2 "math/rand/v2"
	"net"

	"github.com/metacubex/mihomo/log"

	utls "github.com/metacubex/utls"
)

// BadVPN P20: the Chrome 155 ClientHello.
//
// Xray-core 26.11.9 made hellochrome_155 its default fingerprint
// (XTLS/Xray-core#7135); the profile itself comes from
// refraction-networking/utls 6ebdceb2, verified there against a capture of
// Chrome 155.0.8059.40. metacubex/utls (the utls this core builds on) stops at
// Chrome 133, so the spec lives here and is applied through HelloCustom until
// that fork ships HelloChrome_155.
//
// Compared with Chrome 133 the hello gains a GREASE value and three ML-DSA
// schemes in signature_algorithms and the trust_anchors extension (0xca34)
// with 28 Chrome Root Store IDs.

// HelloChrome155 names the profile. utls does not know the version, so the ID
// must reach utls only through UClient and fingerprintSpec in this package.
var HelloChrome155 = UClientHelloID{Client: utls.HelloChrome_133.Client, Version: "155"}

// HelloChromeAuto is what "chrome" (and an empty REALITY fingerprint) means.
var HelloChromeAuto = HelloChrome155

const (
	extensionTrustAnchors uint16 = 0xca34 // draft-ietf-tls-trust-anchor-ids

	sigSchemeMLDSA44 utls.SignatureScheme = 0x0904
	sigSchemeMLDSA65 utls.SignatureScheme = 0x0905
	sigSchemeMLDSA87 utls.SignatureScheme = 0x0906
)

// chrome155TrustAnchorIDs are the Chrome Root Store IDs a fresh Chrome
// 155.0.8059.40 advertises, in the captured (lexicographic) order.
var chrome155TrustAnchorIDs = [][]byte{
	{0x82, 0xdf, 0x13, 0x02, 0x01},
	{0x82, 0xdf, 0x13, 0x02, 0x06},
	{0x82, 0xdf, 0x13, 0x02, 0x0d},
	{0x82, 0xdf, 0x13, 0x02, 0x0e},
	{0x82, 0xdf, 0x13, 0x02, 0x0f},
	{0x82, 0xdf, 0x13, 0x02, 0x12},
	{0x82, 0xdf, 0x13, 0x02, 0x13},
	{0x82, 0xdf, 0x13, 0x02, 0x14},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13},
	{0xd6, 0x79, 0x09, 0x01},
	{0xd6, 0x79, 0x09, 0x04},
	{0xd6, 0x79, 0x09, 0x05},
	{0xd6, 0x79, 0x09, 0x06},
	{0xd6, 0x79, 0x09, 0x07},
	{0xd6, 0x79, 0x09, 0x08},
	{0xd6, 0x79, 0x09, 0x0a},
	{0xd6, 0x79, 0x09, 0x0b},
	{0xd6, 0x79, 0x09, 0x0c},
	{0xd6, 0x79, 0x09, 0x0d},
	{0xd6, 0x79, 0x09, 0x0f},
}

// chrome155TrustAnchorsData is the extension_data of trust_anchors: a
// two-byte list length, then every ID behind its one-byte length.
func chrome155TrustAnchorsData() []byte {
	data := []byte{0, 0}
	for _, id := range chrome155TrustAnchorIDs {
		data = append(data, byte(len(id)))
		data = append(data, id...)
	}
	listLen := len(data) - 2
	data[0], data[1] = byte(listLen>>8), byte(listLen)
	return data
}

// chrome155Spec returns a fresh spec: utls mutates it per connection.
func chrome155Spec() utls.ClientHelloSpec {
	// The utls in use replaces GREASE placeholders in cipher suites, groups,
	// key shares and versions but leaves signature_algorithms alone, so the
	// value is drawn here. BoringSSL draws every GREASE value independently.
	greaseSigScheme := utls.SignatureScheme(uint16(randv2.IntN(16))*0x1010 + 0x0a0a)

	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions: utls.ShuffleChromeTLSExtensions([]utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				greaseSigScheme,
				sigSchemeMLDSA44,
				sigSchemeMLDSA65,
				sigSchemeMLDSA87,
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			&utls.GenericExtension{Id: extensionTrustAnchors, Data: chrome155TrustAnchorsData()},
			utls.BoringGREASEECH(),
			&utls.UtlsGREASEExtension{},
		}),
	}
}

// fingerprintSpec is utls.UTLSIdToSpec that also knows the profiles defined in
// this package.
func fingerprintSpec(id UClientHelloID) (utls.ClientHelloSpec, error) {
	if id == HelloChrome155 {
		return chrome155Spec(), nil
	}
	return utls.UTLSIdToSpec(id)
}

// uClient is utls.UClient that also knows the profiles defined in this
// package. Every utls client in the core must be created through it (or
// through UClient): utls.UClient fails to build a hello for HelloChrome155.
func uClient(c net.Conn, config *utls.Config, fingerprint UClientHelloID) *UConn {
	if fingerprint == HelloChrome155 {
		uConn := utls.UClient(c, config, utls.HelloCustom)
		spec := chrome155Spec()
		if err := uConn.ApplyPreset(&spec); err == nil {
			return uConn
		} else {
			// Only a failing random source or a malformed spec gets here; the
			// previous chrome profile is the closest hello that still works.
			log.Warnln("chrome 155 fingerprint: %v, using chrome 133", err)
		}
		fingerprint = utls.HelloChrome_133
	}
	return utls.UClient(c, config, fingerprint)
}
