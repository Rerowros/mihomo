package route

import (
	stdnet "net"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

func controllerTLSHandshake(addr string, maxVersion uint16) (uint16, error) {
	conn, err := stdnet.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         maxVersion,
	})
	if err := tlsConn.Handshake(); err != nil {
		return 0, err
	}
	return tlsConn.ConnectionState().Version, nil
}

// external-controller-tls refuses TLS 1.0 and 1.1 and accepts 1.2 and 1.3.
func TestControllerTLSMinVersion(t *testing.T) {
	resetServers(t)
	addr := freeLoopbackAddr(t)
	// Empty certificate and key: the controller uses a random self-signed pair.
	ReCreateServer(&Config{TLSAddr: addr, Secret: testSecret})

	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if got, err := controllerTLSHandshake(addr, v); err == nil {
			t.Errorf("handshake with max version %#x succeeded with %#x, want refusal", v, got)
		}
	}
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		got, err := controllerTLSHandshake(addr, v)
		if err != nil {
			t.Errorf("handshake with max version %#x: %v", v, err)
		} else if got != v {
			t.Errorf("handshake with max version %#x negotiated %#x", v, got)
		}
	}
}
