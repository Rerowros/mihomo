package inbound_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/fragment"
	"github.com/metacubex/mihomo/component/fragment/dpifilter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// TestBPNFragmentXrayInterop (P19) runs a real Xray-core server on 127.0.0.1
// with REALITY and TLS inbounds and puts the filter model (dpifilter.Record:
// resets the connection when one TLS record holds a whole ClientHello with
// SNI) in front of each inbound. Without fragment-opts the filter must reset
// the connection; with packets "tlshello" the handshake must reach Xray and a
// 1 MiB echo through the tunnel must match by sha256.
//
//	XRAY_BINARY=/path/to/xray go test ./listener/inbound -run BPNFragmentXrayInterop -v -count=1
func TestBPNFragmentXrayInterop(t *testing.T) {
	xrayBinary := os.Getenv("XRAY_BINARY")
	if xrayBinary == "" {
		t.Skip("XRAY_BINARY is not set; point it at an Xray-core executable")
	}
	versionOutput, err := exec.Command(xrayBinary, "version").CombinedOutput()
	require.NoError(t, err, "xray version: %s", versionOutput)
	xrayVersion := strings.Fields(string(versionOutput))[1]
	t.Logf("Xray executable: %s (%s)", xrayBinary, xrayVersion)
	mlkem := bpnMatrixVersionAtLeast(t, xrayVersion, 26, 9, 8)

	echoAddr := startVMessInteropEcho(t)
	targetAddr := startTLSMirrorInteropCarrierTLS(t).addr
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, []byte(tlsCertificate), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte(tlsPrivateKey), 0o600))

	realitySettings := map[string]any{
		"dest":        targetAddr,
		"serverNames": []string{"localhost"},
		"privateKey":  base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
		"shortIds":    []string{bpnMatrixShortID},
	}
	tlsSettings := map[string]any{
		"alpn":         []string{"h2", "http/1.1"},
		"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}},
	}
	vlessClients := func(flow string) map[string]any {
		return map[string]any{"clients": []any{map[string]any{"id": bpnMatrixUUID, "flow": flow}}, "decryption": "none"}
	}
	realityOpts := outbound.RealityOptions{PublicKey: publicKey, ShortID: bpnMatrixShortID, SupportX25519MLKEM768: mlkem}

	type inboundCase struct {
		name    string
		inbound map[string]any
		client  func(port int, basic outbound.BasicOption) (C.ProxyAdapter, error)
	}
	vless := func(network, security string, settings map[string]any, flow string, extra map[string]any) map[string]any {
		stream := map[string]any{"network": network, "security": security}
		if security == "reality" {
			stream["realitySettings"] = settings
		} else {
			stream["tlsSettings"] = settings
		}
		for k, v := range extra {
			stream[k] = v
		}
		return map[string]any{"protocol": "vless", "settings": vlessClients(flow), "streamSettings": stream}
	}
	newVless := func(o outbound.VlessOption) func(int, outbound.BasicOption) (C.ProxyAdapter, error) {
		return func(port int, basic outbound.BasicOption) (C.ProxyAdapter, error) {
			o.BasicOption, o.Name, o.Server, o.Port, o.UUID, o.TLS = basic, "bpn_fragment", "127.0.0.1", port, bpnMatrixUUID, true
			if o.RealityOpts.PublicKey != "" {
				o.ServerName, o.ClientFingerprint = "localhost", "chrome"
			} else {
				o.ServerName, o.SkipCertVerify = "example.com", true
			}
			return outbound.NewVless(o)
		}
	}
	cases := []inboundCase{
		{"vless-reality-tcp", vless("tcp", "reality", realitySettings, "", nil),
			newVless(outbound.VlessOption{RealityOpts: realityOpts})},
		{"vless-reality-vision", vless("tcp", "reality", realitySettings, "xtls-rprx-vision", nil),
			newVless(outbound.VlessOption{RealityOpts: realityOpts, Flow: "xtls-rprx-vision"})},
		{"vless-reality-xhttp", vless("xhttp", "reality", realitySettings, "", map[string]any{"xhttpSettings": map[string]any{"path": "/x", "mode": "stream-one"}}),
			newVless(outbound.VlessOption{RealityOpts: realityOpts, Network: "xhttp", XHTTPOpts: outbound.XHTTPOptions{Path: "/x", Mode: "stream-one"}})},
		{"vless-tls-tcp", vless("tcp", "tls", tlsSettings, "", nil),
			newVless(outbound.VlessOption{})},
		{"vless-tls-ws", vless("ws", "tls", tlsSettings, "", map[string]any{"wsSettings": map[string]any{"path": "/ws"}}),
			newVless(outbound.VlessOption{Network: "ws", ALPN: []string{"http/1.1"}, WSOpts: outbound.WSOptions{Path: "/ws"}})},
		{"vless-tls-grpc", vless("grpc", "tls", tlsSettings, "", map[string]any{"grpcSettings": map[string]any{"serviceName": "g"}}),
			newVless(outbound.VlessOption{Network: "grpc", ALPN: []string{"h2"}, GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "g"}})},
		{"vless-tls-xhttp", vless("xhttp", "tls", tlsSettings, "", map[string]any{"xhttpSettings": map[string]any{"path": "/x", "mode": "packet-up"}}),
			newVless(outbound.VlessOption{Network: "xhttp", ALPN: []string{"h2"}, XHTTPOpts: outbound.XHTTPOptions{Path: "/x", Mode: "packet-up"}})},
		{"trojan-tls-tcp", map[string]any{"protocol": "trojan",
			"settings":       map[string]any{"clients": []any{map[string]any{"password": bpnMatrixUUID}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": tlsSettings}},
			func(port int, basic outbound.BasicOption) (C.ProxyAdapter, error) {
				return outbound.NewTrojan(outbound.TrojanOption{BasicOption: basic, Name: "bpn_fragment", Server: "127.0.0.1", Port: port,
					Password: bpnMatrixUUID, SNI: "example.com", SkipCertVerify: true})
			}},
		{"vmess-tls-ws", map[string]any{"protocol": "vmess",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": bpnMatrixUUID}}},
			"streamSettings": map[string]any{"network": "ws", "security": "tls", "tlsSettings": tlsSettings, "wsSettings": map[string]any{"path": "/vm"}}},
			func(port int, basic outbound.BasicOption) (C.ProxyAdapter, error) {
				return outbound.NewVmess(outbound.VmessOption{BasicOption: basic, Name: "bpn_fragment", Server: "127.0.0.1", Port: port,
					UUID: bpnMatrixUUID, Cipher: "auto", TLS: true, ServerName: "example.com", SkipCertVerify: true,
					Network: "ws", ALPN: []string{"http/1.1"}, WSOpts: outbound.WSOptions{Path: "/vm"}})
			}},
	}

	ports := make([]*vmessInteropReservedTCPPort, len(cases))
	inbounds := make([]any, len(cases))
	for i, c := range cases {
		ports[i] = vmessInteropReserveTCPPort(t)
		c.inbound["listen"], c.inbound["port"] = "127.0.0.1", ports[i].Port()
		inbounds[i] = c.inbound
	}
	config, err := json.MarshalIndent(map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": inbounds,
		"outbounds": []any{map[string]any{"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}}}},
	}, "", "  ")
	require.NoError(t, err)
	for _, p := range ports[1:] {
		p.Release()
	}
	bpnMatrixStartXray(t, xrayBinary, config, ports[0])
	bpnMatrixWarmUp(t, ports[0].Port(), targetAddr)

	variants := []struct {
		name string
		opts fragment.Options
		pass bool
	}{
		{"off", fragment.Options{}, false},
		{"tlshello-10-20-delay-0", fragment.Options{Packets: "tlshello", Length: "10-20", Delay: "0"}, true},
		{"tlshello-10-20-delay-1", fragment.Options{Packets: "tlshello", Length: "10-20", Delay: "1"}, true},
	}
	for i, c := range cases {
		upstream := net.JoinHostPort("127.0.0.1", fmt.Sprint(ports[i].Port()))
		for _, v := range variants {
			t.Run(c.name+"/"+v.name, func(t *testing.T) {
				filter, err := dpifilter.Start(upstream, dpifilter.Record)
				require.NoError(t, err)
				t.Cleanup(func() { _ = filter.Close() })
				_, filterPort, _ := net.SplitHostPort(filter.Addr())
				out, err := c.client(vmessInteropParsePort(t, filterPort), outbound.BasicOption{FragmentOpts: v.opts})
				require.NoError(t, err)
				t.Cleanup(func() { _ = out.Close() })

				err = bpnFragmentEcho(t, out, echoAddr, 1<<20)
				t.Logf("FRAGMENT xray=%s %s %s -> err=%v blocked=%d passed=%d", xrayVersion, c.name, v.name, err, filter.Blocked(), filter.Passed())
				if v.pass {
					require.NoError(t, err)
					require.Zero(t, filter.Blocked())
				} else {
					require.Error(t, err)
					require.NotZero(t, filter.Blocked())
					require.Zero(t, filter.Passed())
				}
			})
		}
	}
}

func bpnFragmentEcho(t *testing.T, out C.ProxyAdapter, echoAddr string, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, vmessInteropMetadata(t, echoAddr))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	writeErr := make(chan error, 1)
	go func() { _, err := conn.Write(payload); writeErr <- err }()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if err := <-writeErr; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if sha256.Sum256(payload) != sha256.Sum256(got) {
		return fmt.Errorf("echo sha256 mismatch")
	}
	return nil
}
