package xrayapi

import (
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"

	"google.golang.org/protobuf/encoding/protowire"
)

func alterInbound(message []byte) ([]byte, int, string) {
	tag, operation, err := decodeAlterInbound(message)
	if err != nil {
		return nil, 3, err.Error()
	}
	if tag == "" {
		return nil, 3, "inbound tag is empty"
	}
	switch operation.Type {
	case "xray.app.proxyman.command.AddUserOperation":
		return addUser(tag, operation.Value)
	case "xray.app.proxyman.command.RemoveUserOperation":
		return removeUser(tag, operation.Value)
	default:
		return nil, 12, "unknown operation " + operation.Type
	}
}

func addUser(tag string, operation []byte) ([]byte, int, string) {
	user, err := decodeAddUserOperation(operation)
	if err != nil {
		return nil, 3, err.Error()
	}
	if user.Email == "" {
		return nil, 3, "user email is empty"
	}
	if user.Account.Type != "xray.proxy.vless.Account" {
		return nil, 3, "only VLESS accounts are supported, got " + user.Account.Type
	}
	account, err := accountUser(user.Account)
	if err != nil {
		return nil, 3, err.Error()
	}
	if account.UUID == "" {
		return nil, 3, "user id is empty"
	}

	_, err = listener.UpdateInboundUsers(tag, func(users []C.InboundUser) ([]C.InboundUser, error) {
		for i := range users {
			if strings.EqualFold(users[i].Username, user.Email) {
				return nil, C.ErrInboundUserExists
			}
		}
		return append(users, C.InboundUser{
			Username: user.Email,
			UUID:     account.UUID,
			Flow:     account.Flow,
		}), nil
	})
	if err != nil {
		if errors.Is(err, C.ErrInboundUserExists) {
			return nil, 6, "user " + user.Email + " already exists"
		}
		return nil, userErrorCode(err), "failed to get handler: " + err.Error()
	}
	return nil, 0, ""
}

func removeUser(tag string, operation []byte) ([]byte, int, string) {
	email, err := decodeRemoveUserOperation(operation)
	if err != nil {
		return nil, 3, err.Error()
	}
	if email == "" {
		return nil, 3, "user email is empty"
	}
	// The listener revokes the removed user and closes its connections.
	_, err = listener.UpdateInboundUsers(tag, func(users []C.InboundUser) ([]C.InboundUser, error) {
		kept := make([]C.InboundUser, 0, len(users))
		found := false
		for _, user := range users {
			if strings.EqualFold(user.Username, email) {
				found = true
				continue
			}
			kept = append(kept, user)
		}
		if !found {
			return nil, C.ErrInboundUserNotFound
		}
		return kept, nil
	})
	if err != nil {
		return nil, userErrorCode(err), "failed to get handler: " + err.Error()
	}
	return nil, 0, ""
}

func getInboundUsers(message []byte) ([]byte, int, string) {
	tag, email, err := decodeInboundUserRequest(message)
	if err != nil {
		return nil, 3, err.Error()
	}
	users, err := listener.GetInboundUsers(tag)
	if err != nil {
		return nil, userErrorCode(err), "failed to get handler: " + err.Error()
	}
	var response []byte
	for _, user := range users {
		if email != "" && !strings.EqualFold(user.Username, email) {
			continue
		}
		response = appendMessage(response, 1, encodeUser(user.Username, user.UUID, user.Flow))
	}
	return response, 0, ""
}

func getInboundUsersCount(message []byte) ([]byte, int, string) {
	tag, _, err := decodeInboundUserRequest(message)
	if err != nil {
		return nil, 3, err.Error()
	}
	users, err := listener.GetInboundUsers(tag)
	if err != nil {
		return nil, userErrorCode(err), "failed to get handler: " + err.Error()
	}
	return appendVarint(nil, 1, uint64(len(users))), 0, ""
}

func listInbounds(message []byte) ([]byte, int, string) {
	var response []byte
	for _, name := range listener.InboundListenerNames() {
		response = appendMessage(response, 1, encodeInboundConfig(name))
	}
	return response, 0, ""
}

func decodeInboundUserRequest(data []byte) (tag, email string, err error) {
	err = walkFields(data, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		switch num {
		case 1:
			tag = string(b)
		case 2:
			email = string(b)
		}
		return nil
	})
	return
}

func userErrorCode(err error) int {
	switch {
	case errors.Is(err, C.ErrInboundNotFound):
		return 5
	case errors.Is(err, C.ErrInboundNoUserTable):
		return 9
	case errors.Is(err, C.ErrInvalidInboundUser), errors.Is(err, C.ErrInboundUserExists):
		return 3
	case errors.Is(err, C.ErrInboundUserNotFound):
		return 5
	}
	if strings.Contains(err.Error(), "not supported") {
		return 12
	}
	return 13
}
