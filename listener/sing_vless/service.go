package sing_vless

// copy and modify from https://github.com/SagerNet/sing-vmess/tree/3c1cf255413250b09a57e4ecdf1def1fa505e3cc/vless

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/vless"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"google.golang.org/protobuf/proto"
)

// userEntry is the record of one user. A record that stays the same across
// table updates keeps its sessions; a removed or re-keyed one is revoked and
// closes every connection bound to it. Bind and revoke take entry.mu, so a
// connection either binds before the revocation (and is closed by it) or sees
// it (and is dropped): no connection of a removed user slips through.
type userEntry struct {
	name string
	flow string

	revoked  atomic.Bool
	mu       sync.Mutex
	sessions map[*boundSession]struct{}
}

type boundSession struct {
	closer  io.Closer
	tracked bool
}

var _ C.InboundSession = (*userEntry)(nil)

func (e *userEntry) Revoked() bool {
	return e.revoked.Load()
}

func (e *userEntry) Bind(c io.Closer, tracked bool) (release func(), ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.revoked.Load() {
		return func() {}, false
	}
	session := &boundSession{closer: c, tracked: tracked}
	if e.sessions == nil {
		e.sessions = make(map[*boundSession]struct{})
	}
	e.sessions[session] = struct{}{}
	return func() {
		e.mu.Lock()
		delete(e.sessions, session)
		e.mu.Unlock()
	}, true
}

// revoke marks the record removed and returns the sessions to close.
func (e *userEntry) revoke() []*boundSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revoked.Store(true)
	sessions := make([]*boundSession, 0, len(e.sessions))
	for session := range e.sessions {
		sessions = append(sessions, session)
	}
	e.sessions = nil
	return sessions
}

// userTable is published as one immutable snapshot, so a runtime user update
// never races with a handshake that is reading the table. users keeps the
// table as it was given (UUID strings as written) for GetUsers.
type userTable struct {
	byKey map[[16]byte]*userEntry
	users []LC.VlessUser
}

type Service struct {
	users    atomic.Pointer[userTable]
	updateMu sync.Mutex
	handler  Handler
}

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
	E.Handler
}

func NewService(handler Handler) *Service {
	s := &Service{
		handler: handler,
	}
	s.users.Store(&userTable{byKey: make(map[[16]byte]*userEntry)})
	return s
}

// UpdateUsers replaces the user table. A user whose record (name, key, flow)
// is unchanged keeps its entry and its sessions; every other old entry is
// revoked and its connections are closed. Callers validate the list; if two
// users still share a key (old configs), the later one wins.
func (s *Service) UpdateUsers(users []LC.VlessUser) C.InboundUserChange {
	s.updateMu.Lock()
	old := s.users.Load()
	next := &userTable{
		byKey: make(map[[16]byte]*userEntry, len(users)),
		users: append([]LC.VlessUser(nil), users...),
	}
	for _, user := range users {
		key := utils.UUIDMap(user.UUID)
		if previous := old.byKey[key]; previous != nil && previous.name == user.Username && previous.flow == user.Flow {
			next.byKey[key] = previous
			continue
		}
		next.byKey[key] = &userEntry{name: user.Username, flow: user.Flow}
	}
	s.users.Store(next)
	var change C.InboundUserChange
	var sessions []*boundSession
	for key, entry := range old.byKey {
		if next.byKey[key] == entry {
			continue
		}
		change.Revoked = append(change.Revoked, entry.name)
		sessions = append(sessions, entry.revoke()...)
	}
	s.updateMu.Unlock()

	for _, session := range sessions {
		_ = session.closer.Close()
		if session.tracked {
			change.Closed++
		}
	}
	sort.Strings(change.Revoked)
	return change
}

// Users returns the current table as it was given.
func (s *Service) Users() []LC.VlessUser {
	return append([]LC.VlessUser(nil), s.users.Load().users...)
}

// testHookBeforeBind runs between the table lookup and Bind; tests use it to
// revoke the user in that window.
var testHookBeforeBind func()

var _ N.TCPConnectionHandler = (*Service)(nil)

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	var version uint8
	err := binary.Read(conn, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	if version != vless.Version {
		return E.New("unknown version: ", version)
	}

	var requestUUID [16]byte
	_, err = io.ReadFull(conn, requestUUID[:])
	if err != nil {
		return err
	}

	var addonsLen uint8
	err = binary.Read(conn, binary.BigEndian, &addonsLen)
	if err != nil {
		return err
	}

	var addons vless.Addons
	if addonsLen > 0 {
		addonsBytes := make([]byte, addonsLen)
		_, err = io.ReadFull(conn, addonsBytes)
		if err != nil {
			return err
		}

		err = proto.Unmarshal(addonsBytes, &addons)
		if err != nil {
			return err
		}
	}

	var command byte
	err = binary.Read(conn, binary.BigEndian, &command)
	if err != nil {
		return err
	}

	var destination M.Socksaddr
	if command != vless.CommandMux {
		destination, err = vmess.AddressSerializer.ReadAddrPort(conn)
		if err != nil {
			return err
		}
	}

	entry := s.users.Load().byKey[requestUUID]
	if entry == nil {
		return E.New("unknown UUID: ", uuid.FromBytesOrNil(requestUUID[:]))
	}
	ctx = auth.ContextWithUser(ctx, entry.name)
	metadata.Destination = destination

	userFlow := entry.flow
	requestFlow := addons.Flow
	if requestFlow != userFlow && requestFlow != "" {
		return E.New("flow mismatch: expected ", flowName(userFlow), ", but got ", flowName(requestFlow))
	}

	if testHookBeforeBind != nil {
		testHookBeforeBind()
	}
	// Bind the client connection to the user's record: removing the user
	// closes it, which ends the TCP relay, the UDP loop and mux streams.
	release, ok := entry.Bind(conn, false)
	if !ok {
		return E.New("user ", entry.name, " removed")
	}
	defer release()
	ctx = sing.WithInboundSession(ctx, entry)

	responseConn := &serverConn{ExtendedConn: bufio.NewExtendedConn(conn)}
	switch requestFlow {
	case vless.XRV:
		conn, err = vision.NewConn(responseConn, conn, requestUUID)
		if err != nil {
			return E.Cause(err, "initialize vision")
		}
	case "":
		conn = responseConn
	default:
		return E.New("unknown flow: ", requestFlow)
	}
	switch command {
	case vless.CommandTCP:
		return s.handler.NewConnection(ctx, conn, metadata)
	case vless.CommandUDP:
		if requestFlow == vless.XRV {
			return E.New(vless.XRV, " flow does not support UDP")
		}
		return s.handler.NewPacketConnection(ctx, &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(conn), destination: destination}, metadata)
	case vless.CommandMux:
		return vmess.HandleMuxConnection(ctx, conn, metadata, s.handler)
	default:
		return E.New("unknown command: ", command)
	}
}

func flowName(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

type serverConn struct {
	N.ExtendedConn
	responseWritten bool
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if !c.responseWritten {
		buffer := buf.NewSize(2 + len(b))
		buffer.WriteByte(vless.Version)
		buffer.WriteByte(0)
		buffer.Write(b)
		_, err = c.ExtendedConn.Write(buffer.Bytes())
		buffer.Release()
		if err == nil {
			n = len(b)
		}
		c.responseWritten = true
		return
	}
	return c.ExtendedConn.Write(b)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.responseWritten {
		header := buffer.ExtendHeader(2)
		header[0] = vless.Version
		header[1] = 0
		c.responseWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverConn) FrontHeadroom() int {
	if c.responseWritten {
		return 0
	}
	return 2
}

func (c *serverConn) ReaderReplaceable() bool {
	return true
}

func (c *serverConn) WriterReplaceable() bool {
	return c.responseWritten
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.ExtendedConn
}

type serverPacketConn struct {
	N.ExtendedConn
	destination     M.Socksaddr
	readWaitOptions N.ReadWaitOptions
}

func (c *serverPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

func (c *serverPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	buffer = c.readWaitOptions.NewPacketBuffer()
	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		buffer.Release()
		return
	}
	c.readWaitOptions.PostReturn(buffer)

	destination = c.destination
	return
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}
	if len(p) < int(packetLen) {
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(c.ExtendedConn, p[:packetLen])
	if err != nil {
		return
	}
	if c.destination.IsFqdn() {
		addr = c.destination
	} else {
		addr = c.destination.UDPAddr()
	}
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = binary.Write(c.ExtendedConn, binary.BigEndian, uint16(len(p)))
	if err != nil {
		return
	}
	return c.ExtendedConn.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		return
	}

	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	packetLen := buffer.Len()
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(packetLen))
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverPacketConn) FrontHeadroom() int {
	return 2
}

func (c *serverPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverPacketConn) Upstream() any {
	return c.ExtendedConn
}
