package inbound_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revokeRecorder is a tunnel that echoes TCP and UDP and counts what reached
// it per inbound user: after a user is removed nothing of theirs may arrive.
type revokeRecorder struct {
	mu       sync.Mutex
	tcpBytes map[string]int
	udpPkts  map[string]int
	onTCP    func(conn net.Conn, metadata *C.Metadata) bool
}

func newRevokeRecorder() *revokeRecorder {
	return &revokeRecorder{tcpBytes: map[string]int{}, udpPkts: map[string]int{}}
}

func (r *revokeRecorder) tcp(user string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tcpBytes[user]
}

func (r *revokeRecorder) udp(user string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.udpPkts[user]
}

func (r *revokeRecorder) tunnel() *TestTunnel {
	return &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			defer conn.Close()
			r.mu.Lock()
			hook := r.onTCP
			r.mu.Unlock()
			if hook != nil && hook(conn, metadata) {
				return
			}
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					r.mu.Lock()
					r.tcpBytes[metadata.InUser] += n
					r.mu.Unlock()
					if _, werr := conn.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			defer packet.Drop()
			r.mu.Lock()
			r.udpPkts[metadata.InUser]++
			r.mu.Unlock()
			_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr())
		},
		CloseFn:     func() error { return nil },
		NewDialerFn: func() C.Dialer { return dialer.NewDialer() },
	}
}

func startRevokeVless(t *testing.T, rec *revokeRecorder, users []inbound.VlessUser, mod func(*inbound.VlessOption)) (*inbound.Vless, netip.AddrPort) {
	t.Helper()
	options := inbound.VlessOption{
		BaseOption: inbound.BaseOption{
			NameStr: "vless_revoke",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:         users,
		AllowInsecure: true,
	}
	if mod != nil {
		mod(&options)
	}
	in, err := inbound.NewVless(&options)
	require.NoError(t, err)
	require.NoError(t, in.Listen(rec.tunnel()))
	t.Cleanup(func() { _ = in.Close() })
	addrPort, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	return in, addrPort
}

func newRevokeClient(t *testing.T, addr netip.AddrPort, uuid string, mod func(*outbound.VlessOption)) outbound.ProxyAdapter {
	t.Helper()
	options := outbound.VlessOption{
		Name:   "vless_revoke_out",
		Server: addr.Addr().String(),
		Port:   int(addr.Port()),
		UUID:   uuid,
		UDP:    true,
	}
	options.DialerForAPI = dialer.NewDialer()
	if mod != nil {
		mod(&options)
	}
	out, err := outbound.NewVless(options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

// withTimeout runs fn and reports whether it finished within d.
func withTimeout(d time.Duration, fn func() error) (err error, timedOut bool) {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err = <-done:
		return err, false
	case <-time.After(d):
		return nil, true
	}
}

var revokeTCPMetadata = &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80}
var revokeUDPMetadata = &C.Metadata{NetWork: C.UDP, DstIP: remoteAddr, DstPort: 53}
var revokeUDPTarget = net.UDPAddrFromAddrPort(netip.AddrPortFrom(remoteAddr, 53))

func dialEcho(t *testing.T, out outbound.ProxyAdapter) net.Conn {
	t.Helper()
	conn, err := out.DialContext(context.Background(), revokeTCPMetadata)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	assertEcho(t, conn)
	return conn
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	err, timedOut := withTimeout(5*time.Second, func() error {
		_, err := ioReadFull(conn, buf)
		return err
	})
	require.False(t, timedOut, "echo timed out")
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf))
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// assertTCPClosed checks that the session no longer relays: the write may be
// buffered, but the read must end with an error instead of an echo.
func assertTCPClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_, _ = conn.Write([]byte("pong"))
	buf := make([]byte, 4)
	err, timedOut := withTimeout(3*time.Second, func() error {
		_, err := ioReadFull(conn, buf)
		return err
	})
	assert.False(t, timedOut, "session still open: read timed out instead of failing")
	assert.Error(t, err, "session still relays after the user was removed")
}

func listenUDPEcho(t *testing.T, out outbound.ProxyAdapter) C.PacketConn {
	t.Helper()
	pc, err := out.ListenPacketContext(context.Background(), revokeUDPMetadata)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	assertUDPEcho(t, pc)
	return pc
}

func assertUDPEcho(t *testing.T, pc C.PacketConn) {
	t.Helper()
	_, err := pc.WriteTo([]byte("ping"), revokeUDPTarget)
	require.NoError(t, err)
	buf := make([]byte, 64)
	var n int
	err, timedOut := withTimeout(5*time.Second, func() error {
		var err error
		n, _, err = pc.ReadFrom(buf)
		return err
	})
	require.False(t, timedOut, "udp echo timed out")
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))
}

// assertUDPRevoked sends more packets on the association of a removed user:
// none may reach the tunnel and the client association must end.
func assertUDPRevoked(t *testing.T, rec *revokeRecorder, pc C.PacketConn, user string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	before := rec.udp(user)
	for i := 0; i < 5; i++ {
		_, _ = pc.WriteTo([]byte("late"), revokeUDPTarget)
	}
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, before, rec.udp(user), "packets of a removed user reached the tunnel")
	buf := make([]byte, 64)
	err, timedOut := withTimeout(3*time.Second, func() error {
		_, _, err := pc.ReadFrom(buf)
		return err
	})
	assert.False(t, timedOut, "udp association still open")
	assert.Error(t, err, "udp association still relays")
}

func twoUsers() (uuidA, uuidB string, users []inbound.VlessUser) {
	uuidA = utils.NewUUIDV4().String()
	uuidB = utils.NewUUIDV4().String()
	return uuidA, uuidB, []inbound.VlessUser{
		{Username: "a", UUID: uuidA},
		{Username: "b", UUID: uuidB},
	}
}

// T1: a removed user's VLESS UDP (packetaddr) loop stops.
func TestVlessRevokeUDP(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA, uuidB, users := twoUsers()
	in, addr := startRevokeVless(t, rec, users, nil)
	out := newRevokeClient(t, addr, uuidA, func(o *outbound.VlessOption) { o.PacketEncoding = "packetaddr" })
	pc := listenUDPEcho(t, out)

	setVlessUsers(t, in, []C.InboundUser{{Username: "b", UUID: uuidB}})
	assertUDPRevoked(t, rec, pc, "a")
}

// T2: the same over mux.cool/XUDP, the default packet encoding.
func TestVlessRevokeXUDP(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA, uuidB, users := twoUsers()
	in, addr := startRevokeVless(t, rec, users, nil)
	out := newRevokeClient(t, addr, uuidA, nil)
	pc := listenUDPEcho(t, out)

	setVlessUsers(t, in, []C.InboundUser{{Username: "b", UUID: uuidB}})
	assertUDPRevoked(t, rec, pc, "a")
}

// T3: sing-mux over VLESS: the open stream ends and a new stream of the removed
// user does not reach the tunnel.
func TestVlessRevokeSingMux(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA, uuidB, users := twoUsers()
	in, addr := startRevokeVless(t, rec, users, nil)
	base := newRevokeClient(t, addr, uuidA, nil)
	out, err := outbound.NewSingMux(outbound.SingMuxOption{Enabled: true, Protocol: "smux"}, &notCloseProxyAdapter{base})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	conn := dialEcho(t, out)

	setVlessUsers(t, in, []C.InboundUser{{Username: "b", UUID: uuidB}})
	assertTCPClosed(t, conn)

	before := rec.tcp("a")
	if next, err := out.DialContext(context.Background(), revokeTCPMetadata); err == nil {
		defer next.Close()
		assertTCPClosed(t, next)
	}
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, before, rec.tcp("a"), "a new mux stream of a removed user reached the tunnel")
}

// T4a: a new UUID under the same name ends the sessions of the old UUID and
// rejects it; the new UUID connects.
func TestVlessRevokeUUIDChange(t *testing.T) {
	rec := newRevokeRecorder()
	uuidOld := utils.NewUUIDV4().String()
	uuidNew := utils.NewUUIDV4().String()
	in, addr := startRevokeVless(t, rec, []inbound.VlessUser{{Username: "a", UUID: uuidOld}}, nil)
	conn := dialEcho(t, newRevokeClient(t, addr, uuidOld, nil))

	setVlessUsers(t, in, []C.InboundUser{{Username: "a", UUID: uuidNew}})
	assertTCPClosed(t, conn)

	before := rec.tcp("a")
	stale, err := newRevokeClient(t, addr, uuidOld, nil).DialContext(context.Background(), revokeTCPMetadata)
	if err == nil {
		defer stale.Close()
		assertTCPClosed(t, stale)
	}
	assert.Equal(t, before, rec.tcp("a"), "old UUID still reaches the tunnel")
	dialEcho(t, newRevokeClient(t, addr, uuidNew, nil))
}

// T5: a session that reached the tunnel and is then revoked is closed even
// though its handshake was already accepted.
func TestVlessRevokeDuringHandshake(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA, uuidB, users := twoUsers()
	in, addr := startRevokeVless(t, rec, users, nil)

	result := make(chan bool, 1)
	rec.onTCP = func(conn net.Conn, metadata *C.Metadata) bool {
		if metadata.InUser != "a" {
			return false
		}
		setVlessUsers(t, in, []C.InboundUser{{Username: "b", UUID: uuidB}})
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		result <- n > 0
		return true
	}
	conn, err := newRevokeClient(t, addr, uuidA, nil).DialContext(context.Background(), revokeTCPMetadata)
	require.NoError(t, err)
	defer conn.Close()
	_, _ = conn.Write([]byte("first"))
	select {
	case gotData := <-result:
		assert.False(t, gotData, "data of a removed user reached the tunnel")
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel was not reached")
	}
}

// N1: replacing the table with the same records keeps every session.
func TestVlessRevokeKeepsUnchangedUser(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA, uuidB, users := twoUsers()
	in, addr := startRevokeVless(t, rec, users, nil)
	out := newRevokeClient(t, addr, uuidA, func(o *outbound.VlessOption) { o.PacketEncoding = "packetaddr" })
	conn := dialEcho(t, out)
	pc := listenUDPEcho(t, out)

	setVlessUsers(t, in, []C.InboundUser{{Username: "a", UUID: uuidA}, {Username: "b", UUID: uuidB}})
	time.Sleep(200 * time.Millisecond)
	assertEcho(t, conn)
	assertUDPEcho(t, pc)
}

// N2: removing one user leaves the sessions of another user alone.
func TestVlessRevokeOtherUserUntouched(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA, uuidB, users := twoUsers()
	in, addr := startRevokeVless(t, rec, users, nil)
	connA := dialEcho(t, newRevokeClient(t, addr, uuidA, nil))
	connB := dialEcho(t, newRevokeClient(t, addr, uuidB, nil))

	setVlessUsers(t, in, []C.InboundUser{{Username: "b", UUID: uuidB}})
	assertTCPClosed(t, connA)
	assertEcho(t, connB)
}

// S4: over xhttp packet-up and gRPC the removed user's session ends and later
// uploads do not reach the tunnel.
func TestVlessRevokeHTTPTransports(t *testing.T) {
	cases := []struct {
		name string
		in   func(*inbound.VlessOption)
		out  func(*outbound.VlessOption)
	}{
		{
			name: "xhttp-packet-up",
			in: func(o *inbound.VlessOption) {
				o.Certificate, o.PrivateKey = tlsCertificate, tlsPrivateKey
				o.XHTTPConfig = inbound.XHTTPConfig{Path: "/vless-xhttp", Host: "example.com", Mode: "packet-up"}
			},
			out: func(o *outbound.VlessOption) {
				o.TLS, o.Fingerprint, o.ServerName = true, tlsFingerprint, "example.org"
				o.ClientFingerprint = "chrome"
				o.Network = "xhttp"
				o.XHTTPOpts = outbound.XHTTPOptions{Path: "/vless-xhttp", Host: "example.com", Mode: "packet-up"}
			},
		},
		{
			name: "grpc",
			in: func(o *inbound.VlessOption) {
				o.Certificate, o.PrivateKey = tlsCertificate, tlsPrivateKey
				o.GrpcServiceName = "GunService"
			},
			out: func(o *outbound.VlessOption) {
				o.TLS, o.Fingerprint = true, tlsFingerprint
				o.Network = "grpc"
				o.GrpcOpts = outbound.GrpcOptions{GrpcServiceName: "GunService"}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := newRevokeRecorder()
			uuidA, uuidB, users := twoUsers()
			in, addr := startRevokeVless(t, rec, users, tc.in)
			conn := dialEcho(t, newRevokeClient(t, addr, uuidA, tc.out))

			setVlessUsers(t, in, []C.InboundUser{{Username: "b", UUID: uuidB}})
			time.Sleep(200 * time.Millisecond)
			before := rec.tcp("a")
			_, _ = conn.Write([]byte("late"))
			buf := make([]byte, 4)
			err, timedOut := withTimeout(2*time.Second, func() error {
				_, err := ioReadFull(conn, buf)
				return err
			})
			assert.True(t, timedOut || err != nil, "session still relays after the user was removed")
			assert.Equal(t, before, rec.tcp("a"), "upload of a removed user reached the tunnel")
		})
	}
}

// T14: a string id is accepted like in the config; ids that map to one key are
// duplicates; names differing only in case are duplicates.
func TestVlessSetUsersKeys(t *testing.T) {
	rec := newRevokeRecorder()
	in, addr := startRevokeVless(t, rec, nil, nil)

	setVlessUsers(t, in, []C.InboundUser{{Username: "a", UUID: "bpn-user-1"}})
	dialEcho(t, newRevokeClient(t, addr, "bpn-user-1", nil))

	upper := "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
	lower := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	err := trySetVlessUsers(in, []C.InboundUser{{Username: "a", UUID: upper}, {Username: "b", UUID: lower}})
	assert.True(t, errors.Is(err, C.ErrInvalidInboundUser), "same key in two cases: %v", err)

	err = trySetVlessUsers(in, []C.InboundUser{{Username: "Alice", UUID: upper}, {Username: "alice", UUID: utils.NewUUIDV4().String()}})
	assert.True(t, errors.Is(err, C.ErrInvalidInboundUser), "names differing only in case: %v", err)
}

// S-2: duplicates in the config do not stop the inbound from loading: the
// first user is kept, the duplicate (by name in any case, or by id) is dropped.
func TestVlessConfigDropsDuplicateUsers(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA := utils.NewUUIDV4().String()
	uuidB := utils.NewUUIDV4().String()
	in, addr := startRevokeVless(t, rec, []inbound.VlessUser{
		{Username: "Alice", UUID: uuidA},
		{Username: "alice", UUID: uuidB},
		{Username: "bob", UUID: strings.ToUpper(uuidA)},
	}, nil)

	users := in.GetUsers()
	require.Len(t, users, 1)
	assert.Equal(t, "Alice", users[0].Username)
	assert.Equal(t, uuidA, users[0].UUID)

	dialEcho(t, newRevokeClient(t, addr, uuidA, nil))
	assert.Positive(t, rec.tcp("Alice"))
	assert.Zero(t, rec.tcp("bob"))
}

func setVlessUsers(t *testing.T, in *inbound.Vless, users []C.InboundUser) C.InboundUserChange {
	t.Helper()
	change, err := in.SetUsers(users)
	require.NoError(t, err)
	return change
}

func trySetVlessUsers(in *inbound.Vless, users []C.InboundUser) error {
	_, err := in.SetUsers(users)
	return err
}

// T4: the change names the users whose record was revoked; an unchanged
// record and a UUID written in another case are not revoked, and GetUsers
// returns the UUID as it was last written.
func TestVlessSetUsersReportsRevoked(t *testing.T) {
	rec := newRevokeRecorder()
	uuidA := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	uuidB := utils.NewUUIDV4().String()
	in, _ := startRevokeVless(t, rec, []inbound.VlessUser{{Username: "a", UUID: uuidA}, {Username: "b", UUID: uuidB}}, nil)

	change := setVlessUsers(t, in, []C.InboundUser{{Username: "a", UUID: strings.ToUpper(uuidA)}, {Username: "b", UUID: uuidB}})
	assert.Empty(t, change.Revoked, "same key in another case is the same record")
	assert.Equal(t, strings.ToUpper(uuidA), in.GetUsers()[0].UUID)

	change = setVlessUsers(t, in, []C.InboundUser{{Username: "a", UUID: utils.NewUUIDV4().String()}, {Username: "b", UUID: uuidB}})
	assert.Equal(t, []string{"a"}, change.Revoked)

	change = setVlessUsers(t, in, []C.InboundUser{{Username: "b", UUID: uuidB, Flow: "xtls-rprx-vision"}})
	assert.Equal(t, []string{"a", "b"}, change.Revoked, "removed user and flow change")
}
