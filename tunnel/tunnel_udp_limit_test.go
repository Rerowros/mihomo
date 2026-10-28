package tunnel_test

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type limitTestPacket struct {
	data   []byte
	local  net.Addr
	echoes chan []byte
}

func (p *limitTestPacket) Data() []byte { return p.data }
func (p *limitTestPacket) WriteBack(b []byte, _ net.Addr) (int, error) {
	p.echoes <- append([]byte(nil), b...)
	return len(b), nil
}
func (p *limitTestPacket) Drop()               {}
func (p *limitTestPacket) LocalAddr() net.Addr { return p.local }

var setupLimitTunnel sync.Once

// T7: with max-conns 1 every packet of the one admitted association passes;
// only a second association is refused.
func TestUDPMaxConnsCountsAssociations(t *testing.T) {
	setupLimitTunnel.Do(func() {
		tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
		tunnel.SetMode(tunnel.Direct)
		tunnel.OnRunning()
	})

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var received atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received.Add(1)
			_, _ = echo.WriteToUDP(buf[:n], from)
		}
	}()
	echoAddr := echo.LocalAddr().(*net.UDPAddr).AddrPort()

	key := statistic.UserKey{Inbound: "udp-limit-in", User: "udp-limit-user"}
	statistic.DefaultLimitManager.Set(statistic.UserLimit{Inbound: key.Inbound, User: key.User, MaxConns: 1})
	defer statistic.DefaultLimitManager.Delete(key.Inbound, key.User)

	send := func(srcPort uint16, echoes chan []byte) {
		metadata := &C.Metadata{
			NetWork: C.UDP,
			Type:    C.VLESS,
			SrcIP:   netip.MustParseAddr("127.0.0.1"),
			SrcPort: srcPort,
			DstIP:   echoAddr.Addr(),
			DstPort: echoAddr.Port(),
			InName:  key.Inbound,
			InUser:  key.User,
		}
		tunnel.Tunnel.HandleUDPPacket(&limitTestPacket{
			data:   []byte("ping"),
			local:  net.UDPAddrFromAddrPort(netip.AddrPortFrom(metadata.SrcIP, srcPort)),
			echoes: echoes,
		}, metadata)
	}

	first := make(chan []byte, 8)
	for i := 0; i < 3; i++ {
		send(40001, first)
		select {
		case <-first:
		case <-time.After(3 * time.Second):
			t.Fatalf("packet %d of the admitted association was dropped (echo got %d)", i+1, received.Load())
		}
	}
	if got := received.Load(); got != 3 {
		t.Fatalf("echo received %d packets, want 3", got)
	}

	second := make(chan []byte, 8)
	send(40002, second)
	select {
	case <-second:
		t.Fatal("second association passed max-conns 1")
	case <-time.After(500 * time.Millisecond):
	}
}
