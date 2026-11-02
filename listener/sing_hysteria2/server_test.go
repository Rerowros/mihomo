package sing_hysteria2

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type nopTunnel struct{}

func (nopTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata)        { _ = conn.Close() }
func (nopTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}
func (nopTunnel) NatTable() C.NatTable                                     { return nil }

// An unauthenticated client must not be granted an unbounded number of
// concurrent streams (sing-quic defaults to 2^60).
func TestServerStreamLimitBeforeAuth(t *testing.T) {
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(LC.Hysteria2Server{
		Enable:      true,
		Listen:      "127.0.0.1:0",
		Users:       map[string]string{"test": "hysteria2-test-password"},
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}, inbound.ListenConfig{}, nopTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, l.AddrList()[0].String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	opened := 0
	for ; opened <= 4*ServerMaxIncomingStreams; opened++ {
		if _, err := conn.OpenStream(); err != nil {
			break
		}
	}
	if opened != ServerMaxIncomingStreams {
		t.Fatalf("opened %d streams before authentication, want the limit %d", opened, ServerMaxIncomingStreams)
	}
}
