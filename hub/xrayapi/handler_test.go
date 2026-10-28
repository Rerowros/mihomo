package xrayapi

import (
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
)

func startHandlerVless(t *testing.T, name string) {
	t.Helper()
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: "0"},
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener.PatchInboundListeners(map[string]C.InboundListener{name: in}, tunnel.Tunnel, false)
	if _, ok := listener.GetInboundListener(name); !ok {
		t.Fatal("inbound did not start")
	}
	t.Cleanup(func() { _ = in.Close() })
}

func addUserOperation(user []byte) []byte {
	var operation []byte
	operation = appendString(operation, 1, "xray.app.proxyman.command.AddUserOperation")
	return appendBytes(operation, 2, appendMessage(nil, 1, user))
}

func removeUserOperation(email string) []byte {
	var operation []byte
	operation = appendString(operation, 1, "xray.app.proxyman.command.RemoveUserOperation")
	return appendBytes(operation, 2, appendString(nil, 1, email))
}

func alter(tag string, operation []byte) (int, string) {
	var request []byte
	request = appendString(request, 1, tag)
	request = appendMessage(request, 2, operation)
	_, code, message := alterInbound(request)
	return code, message
}

// T12: emails are compared without case, like a panel expects.
func TestAddRemoveUserEmailCase(t *testing.T) {
	tag := "xray-handler-case"
	startHandlerVless(t, tag)

	if code, message := alter(tag, addUserOperation(encodeUser("Alice", utils.NewUUIDV4().String(), ""))); code != 0 {
		t.Fatalf("add Alice: %d %s", code, message)
	}
	if code, message := alter(tag, addUserOperation(encodeUser("alice", utils.NewUUIDV4().String(), ""))); code != 6 {
		t.Fatalf("add alice: code = %d (%s), want 6", code, message)
	}
	if code, message := alter(tag, removeUserOperation("ALICE")); code != 0 {
		t.Fatalf("remove ALICE: %d %s", code, message)
	}
	if users, _ := listener.GetInboundUsers(tag); len(users) != 0 {
		t.Fatalf("users after remove = %+v", users)
	}
}

// T13: a VMess account is not a VLESS user.
func TestAddUserRejectsVMessAccount(t *testing.T) {
	tag := "xray-handler-vmess"
	startHandlerVless(t, tag)

	var accountMsg []byte
	accountMsg = appendString(accountMsg, 1, "xray.proxy.vmess.Account")
	accountMsg = appendBytes(accountMsg, 2, appendString(nil, 1, utils.NewUUIDV4().String()))
	var user []byte
	user = appendString(user, 2, "vmess-user")
	user = appendMessage(user, 3, accountMsg)

	if code, message := alter(tag, addUserOperation(user)); code != 3 {
		t.Fatalf("add vmess account: code = %d (%s), want 3", code, message)
	}
	if users, _ := listener.GetInboundUsers(tag); len(users) != 0 {
		t.Fatalf("users = %+v", users)
	}
}

// One UUID under two emails is refused: its traffic would count for the wrong user.
func TestAddUserRejectsSharedUUID(t *testing.T) {
	tag := "xray-handler-shared-uuid"
	startHandlerVless(t, tag)
	id := utils.NewUUIDV4().String()

	if code, message := alter(tag, addUserOperation(encodeUser("one", id, ""))); code != 0 {
		t.Fatalf("add one: %d %s", code, message)
	}
	if code, message := alter(tag, addUserOperation(encodeUser("two", id, ""))); code != 3 {
		t.Fatalf("add two: code = %d (%s), want 3", code, message)
	}
}
