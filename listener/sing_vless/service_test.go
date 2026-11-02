package sing_vless

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/vless"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type countingHandler struct{ calls int }

func (h *countingHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	h.calls++
	return nil
}

func (h *countingHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	h.calls++
	return nil
}

func (h *countingHandler) NewError(context.Context, error) {}

// S3 (row 12): the user is revoked between the table lookup and Bind; the
// handshake must fail instead of reaching the handler with the old user.
func TestNewConnectionRevokedBeforeBind(t *testing.T) {
	handler := &countingHandler{}
	service := NewService(handler)
	id := utils.NewUUIDV4().String()
	service.UpdateUsers([]LC.VlessUser{{Username: "a", UUID: id}})

	testHookBeforeBind = func() { service.UpdateUsers(nil) }
	defer func() { testHookBeforeBind = nil }()

	key := utils.UUIDMap(id)
	var request bytes.Buffer
	request.WriteByte(vless.Version)
	request.Write(key[:])
	request.WriteByte(0)                // no addons
	request.WriteByte(vless.CommandTCP) // command
	request.Write([]byte{0x01, 0xbb})   // port 443
	request.WriteByte(0x01)             // IPv4
	request.Write([]byte{1, 2, 3, 4})   // address

	server, client := net.Pipe()
	defer client.Close()
	go func() { _, _ = client.Write(request.Bytes()) }()
	err := service.NewConnection(context.Background(), server, M.Metadata{})
	if err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("err = %v, want user removed", err)
	}
	if handler.calls != 0 {
		t.Fatal("a revoked user reached the handler")
	}
}
