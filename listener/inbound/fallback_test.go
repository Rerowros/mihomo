package inbound_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
)

const fallbackHTML = "<html>maintenance</html>"

// fallbackFile is an HTML page for fallback-page in a home directory of its own, where the
// safe-path check lets the listener read it.
func fallbackFile(t *testing.T) string {
	t.Helper()
	return pageFile(t, fallbackHTML)
}

// pageFile is fallbackFile with the page html.
func pageFile(t *testing.T, html string) string {
	t.Helper()
	home := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(old) })
	file := filepath.Join(home, "page.html")
	if err := os.WriteFile(file, []byte(html), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// listenVless starts a VLESS inbound on loopback and returns its address.
func listenVless(t *testing.T, opt inbound.VlessOption) string {
	t.Helper()
	opt.BaseOption = inbound.BaseOption{NameStr: "vless_fallback", Listen: "127.0.0.1", Port: "0"}
	opt.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
	in, err := inbound.NewVless(&opt)
	if err != nil {
		t.Fatal(err)
	}
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { tunnel.Close() })
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	return in.Address()
}

// get asks addr for path with Host host ("" the address) and returns the response and body.
func get(t *testing.T, addr, host, path string) (*http.Response, string) {
	t.Helper()
	return request(t, http.DefaultTransport, http.MethodGet, addr, host, path)
}

// request is get with the method, over rt.
func request(t *testing.T, rt http.RoundTripper, method, addr, host, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	// a timeout: an inbound that is no HTTP server, or holds the request, fails the test
	resp, err := (&http.Client{Transport: rt, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// an upgrade answers a plain request: the body is the raw stream, nothing to read
		return resp, ""
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// fallback-page on an HTTP transport: a request that is not the inbound's own gets the page
// at "/" and a plain 404 elsewhere, while the protocol goes on over the transport. A
// WebSocket path of "/" takes the page into its own handler, XHTTP's page carries none of
// XHTTP's headers, Trojan's WebSocket has it too, a VLESS inbound with no HTTP transport
// takes no page, and a page that cannot be read, or lies outside the safe paths, starts no
// listener.
func TestInboundFallbackPage(t *testing.T) {
	file := fallbackFile(t)
	// isPage asks addr for "/" and wants the page.
	isPage := func(t *testing.T, addr string) *http.Response {
		t.Helper()
		resp, body := get(t, addr, "", "/")
		if resp.StatusCode != http.StatusOK || body != fallbackHTML {
			t.Fatalf("the page: %d %q", resp.StatusCode, body)
		}
		return resp
	}
	t.Run("websocket", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file})
		isPage(t, addr)
		if resp, _ := get(t, addr, "", "/admin"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("another path: %d", resp.StatusCode)
		}
		// A browser opening the inbound's own path is no WebSocket client either.
		if resp, _ := get(t, addr, "", "/ws"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("the path without an upgrade: %d", resp.StatusCode)
		}
	})
	t.Run("websocket at /", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{WsPath: "/", AllowInsecure: true, FallbackPage: file})
		isPage(t, addr)
	})
	t.Run("xhttp", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file,
			XHTTPConfig: inbound.XHTTPConfig{Path: "/x", Host: "example.com", Mode: "auto"}})
		isPage(t, addr)
		if resp, _ := get(t, addr, "other.example.org", "/x"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("another name under the path: %d", resp.StatusCode)
		}
	})
	t.Run("xhttp at /", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file, XHTTPConfig: inbound.XHTTPConfig{Path: "/", Mode: "auto"}})
		resp := isPage(t, addr)
		if resp.Header.Get("X-Padding") != "" {
			t.Fatal("the page carries XHTTP's padding header")
		}
	})
	t.Run("xhttp OPTIONS", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file,
			XHTTPConfig: inbound.XHTTPConfig{Path: "/x", Host: "example.com", Mode: "auto"}})
		// OPTIONS without padding at the inbound's own path: the 200 with the CORS and
		// padding headers of XHTTP would tell the site apart.
		for _, path := range []string{"/x/", "/x/session"} {
			resp, _ := request(t, http.DefaultTransport, http.MethodOptions, addr, "example.com", path)
			if resp.StatusCode == http.StatusOK || hasXHTTPHeaders(resp) {
				t.Fatalf("OPTIONS %s: %d %v", path, resp.StatusCode, resp.Header)
			}
		}
		at := listenVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file, XHTTPConfig: inbound.XHTTPConfig{Path: "/", Mode: "auto"}})
		if resp, _ := request(t, http.DefaultTransport, http.MethodOptions, at, "", "/"); resp.StatusCode == http.StatusOK || hasXHTTPHeaders(resp) {
			t.Fatalf("OPTIONS / at a path of /: %d %v", resp.StatusCode, resp.Header)
		}
		// With its padding an OPTIONS is the inbound's own, as before.
		padded := "/x/?x_padding=" + strings.Repeat("X", 200)
		if resp, _ := request(t, http.DefaultTransport, http.MethodOptions, addr, "example.com", padded); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Padding") == "" {
			t.Fatalf("OPTIONS with padding: %d %v", resp.StatusCode, resp.Header)
		}
	})
	t.Run("grpc", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{GrpcServiceName: "GunService", AllowInsecure: true, FallbackPage: file})
		// gRPC alone serves HTTP/2 only: without TLS a client of prior knowledge (h2c).
		h2c := &http.Transport{Protocols: new(http.Protocols)}
		h2c.Protocols.SetUnencryptedHTTP2(true)
		defer h2c.CloseIdleConnections()
		resp, body := request(t, h2c, http.MethodGet, addr, "", "/")
		if resp.StatusCode != http.StatusOK || body != fallbackHTML || resp.ProtoMajor != 2 {
			t.Fatalf("the page over h2c: %s %d %q", resp.Proto, resp.StatusCode, body)
		}
		if resp, _ := request(t, h2c, http.MethodGet, addr, "", "/GunService/Tun"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("the gun path without gRPC: %d", resp.StatusCode)
		}
	})
	t.Run("trojan websocket", func(t *testing.T) {
		opt := inbound.TrojanOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file,
			BaseOption: inbound.BaseOption{NameStr: "trojan_fallback", Listen: "127.0.0.1", Port: "0"},
			Users:      []inbound.TrojanUser{{Username: "test", Password: userUUID}}}
		in, err := inbound.NewTrojan(&opt)
		if err != nil {
			t.Fatal(err)
		}
		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()
		if err := in.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		isPage(t, in.Address())
	})
	refused := func(t *testing.T, page string) {
		t.Helper()
		opt := inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: page}
		opt.BaseOption = inbound.BaseOption{NameStr: "vless_fallback", Listen: "127.0.0.1", Port: "0"}
		opt.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
		in, err := inbound.NewVless(&opt)
		if err != nil {
			t.Fatal(err)
		}
		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()
		if err := in.Listen(tunnel); err == nil {
			in.Close()
			t.Fatalf("%s starts a listener", page)
		}
	}
	t.Run("a missing page fails the listener", func(t *testing.T) {
		refused(t, filepath.Join(filepath.Dir(file), "none.html"))
	})
	t.Run("a page outside the safe paths fails the listener", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "page.html")
		if err := os.WriteFile(outside, []byte(fallbackHTML), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, outside)
	})
	t.Run("the protocol over websocket", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file},
			outbound.VlessOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/ws"}})
	})
	t.Run("the protocol over websocket at /", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{WsPath: "/", AllowInsecure: true, FallbackPage: file},
			outbound.VlessOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/"}})
	})
	t.Run("the protocol over xhttp", func(t *testing.T) {
		testInboundVlessTLS(t, inbound.VlessOption{
			Certificate:  tlsCertificate,
			PrivateKey:   tlsPrivateKey,
			FallbackPage: file,
			XHTTPConfig:  inbound.XHTTPConfig{Path: "/vless-xhttp", Host: "example.com", Mode: "auto"},
		}, outbound.VlessOption{
			TLS:               true,
			Fingerprint:       tlsFingerprint,
			ServerName:        "example.org",
			ClientFingerprint: "chrome",
			Network:           "xhttp",
			XHTTPOpts:         outbound.XHTTPOptions{Path: "/vless-xhttp", Host: "example.com", Mode: "auto"},
		}, false)
	})
	t.Run("the protocol over grpc", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{GrpcServiceName: "GunService", AllowInsecure: true, FallbackPage: file},
			outbound.VlessOption{Network: "grpc", GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "GunService"}})
	})
	t.Run("the protocol over xhttp packet-up", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file,
			XHTTPConfig: inbound.XHTTPConfig{Path: "/vless-xhttp", Host: "example.com", Mode: "packet-up"}},
			outbound.VlessOption{Network: "xhttp", XHTTPOpts: outbound.XHTTPOptions{Path: "/vless-xhttp", Host: "example.com", Mode: "packet-up"}})
	})
	t.Run("plain vless takes no page", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file}, outbound.VlessOption{})
	})
}

// hasXHTTPHeaders: resp carries a header only XHTTP sets, its padding or CORS.
func hasXHTTPHeaders(resp *http.Response) bool {
	for k := range resp.Header {
		if k == "X-Padding" || strings.HasPrefix(k, "Access-Control-") {
			return true
		}
	}
	return false
}

// The page and the 404 answer HEAD with the headers of GET, Content-Length too, as a web
// server does: left to net/http a page past its buffer goes out chunked, and HEAD without
// a length, which no nginx does.
func TestInboundFallbackPage_Head(t *testing.T) {
	page := "<html>" + strings.Repeat("a", 5000-len("<html></html>")) + "</html>"
	addr := listenVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: pageFile(t, page)})
	for _, tt := range []struct {
		path   string
		code   int
		length string
	}{{"/", http.StatusOK, "5000"}, {"/admin", http.StatusNotFound, "19"}} {
		getResp, body := request(t, http.DefaultTransport, http.MethodGet, addr, "", tt.path)
		headResp, _ := request(t, http.DefaultTransport, http.MethodHead, addr, "", tt.path)
		if getResp.StatusCode != tt.code || headResp.StatusCode != tt.code {
			t.Fatalf("%s: GET %d, HEAD %d", tt.path, getResp.StatusCode, headResp.StatusCode)
		}
		if tt.code == http.StatusOK && body != page {
			t.Fatalf("%s: the page of %d bytes", tt.path, len(body))
		}
		for _, resp := range []*http.Response{getResp, headResp} {
			if got := resp.Header.Get("Content-Length"); got != tt.length || len(resp.TransferEncoding) != 0 {
				t.Fatalf("%s %s: Content-Length %q, Transfer-Encoding %v", resp.Request.Method, tt.path, got, resp.TransferEncoding)
			}
		}
		getResp.Header.Del("Date")
		headResp.Header.Del("Date")
		if !equalHeader(getResp.Header, headResp.Header) {
			t.Fatalf("%s: GET %v, HEAD %v", tt.path, getResp.Header, headResp.Header)
		}
	}
}

func equalHeader(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if strings.Join(v, ",") != strings.Join(b[k], ",") {
			return false
		}
	}
	return true
}

// Without fallback-page nothing changes: a request that is not the inbound's own gets the
// bare 404 of before, under the inbound's path too.
func TestInboundFallbackPage_Off(t *testing.T) {
	notFound := func(t *testing.T, addr, host, path string) {
		t.Helper()
		resp, body := get(t, addr, host, path)
		if resp.StatusCode != http.StatusNotFound || body == fallbackHTML {
			t.Fatalf("%s%s: %d %q", host, path, resp.StatusCode, body)
		}
	}
	t.Run("websocket", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true})
		notFound(t, addr, "", "/")
		notFound(t, addr, "", "/admin")
	})
	t.Run("xhttp", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true,
			XHTTPConfig: inbound.XHTTPConfig{Path: "/x", Host: "example.com", Mode: "auto"}})
		notFound(t, addr, "", "/")
		notFound(t, addr, "other.example.org", "/x")
	})
	t.Run("xhttp OPTIONS as before", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true,
			XHTTPConfig: inbound.XHTTPConfig{Path: "/x", Host: "example.com", Mode: "auto"}})
		if resp, _ := request(t, http.DefaultTransport, http.MethodOptions, addr, "example.com", "/x/"); resp.StatusCode != http.StatusOK {
			t.Fatalf("OPTIONS: %d", resp.StatusCode)
		}
	})
	t.Run("xhttp at / answers a stranger as before", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true, XHTTPConfig: inbound.XHTTPConfig{Path: "/", Mode: "auto"}})
		resp, body := get(t, addr, "", "/")
		if resp.StatusCode != http.StatusBadRequest || body == fallbackHTML {
			t.Fatalf("/: %d %q", resp.StatusCode, body)
		}
	})
}
