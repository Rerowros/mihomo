package xrayapi

import (
	"bytes"
	"testing"
)

func TestUserRoundtrip(t *testing.T) {
	message := encodeUser("bob@example", "11111111-2222-3333-4444-555555555555", "xtls-rprx-vision")
	user, err := decodeUser(message)
	if err != nil {
		t.Fatalf("decode user: %v", err)
	}
	if user.Email != "bob@example" {
		t.Fatalf("email = %q", user.Email)
	}
	if user.Account.Type != "xray.proxy.vless.Account" {
		t.Fatalf("account type = %q", user.Account.Type)
	}
	account, err := accountUser(user.Account)
	if err != nil {
		t.Fatalf("decode account: %v", err)
	}
	if account.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("uuid = %q", account.UUID)
	}
	if account.Flow != "xtls-rprx-vision" {
		t.Fatalf("flow = %q", account.Flow)
	}
}

func TestAlterInboundDecode(t *testing.T) {
	var addUser []byte
	addUser = appendMessage(addUser, 1, encodeUser("bob@example", "11111111-2222-3333-4444-555555555555", ""))

	var operation []byte
	operation = appendString(operation, 1, "xray.app.proxyman.command.AddUserOperation")
	operation = appendBytes(operation, 2, addUser)

	var request []byte
	request = appendString(request, 1, "vless-in")
	request = appendMessage(request, 2, operation)

	tag, op, err := decodeAlterInbound(request)
	if err != nil {
		t.Fatalf("decode alter inbound: %v", err)
	}
	if tag != "vless-in" {
		t.Fatalf("tag = %q", tag)
	}
	if op.Type != "xray.app.proxyman.command.AddUserOperation" {
		t.Fatalf("operation = %q", op.Type)
	}
	user, err := decodeAddUserOperation(op.Value)
	if err != nil {
		t.Fatalf("decode add user: %v", err)
	}
	if user.Email != "bob@example" {
		t.Fatalf("email = %q", user.Email)
	}
}

func TestFrameRoundtrip(t *testing.T) {
	message := []byte("hello")
	framed := frame(message)
	decoded, err := readFrame(framed)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !bytes.Equal(decoded, message) {
		t.Fatalf("decoded = %q", decoded)
	}
	if _, err := readFrame(framed[:4]); err == nil {
		t.Fatal("short frame accepted")
	}
}

func TestDecodeRemoveUser(t *testing.T) {
	email, err := decodeRemoveUserOperation(appendString(nil, 1, "bob@example"))
	if err != nil {
		t.Fatalf("decode remove user: %v", err)
	}
	if email != "bob@example" {
		t.Fatalf("email = %q", email)
	}
}
