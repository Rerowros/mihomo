package xrayapi

import (
	"fmt"
	"runtime"

	"google.golang.org/protobuf/encoding/protowire"
)

// Minimal encoders/decoders for the subset of the Xray API protobuf messages
// that panels use. The wire format and the proto full names are Xray's, so a
// panel cannot tell this server from xray-core.

type typedMessage struct {
	Type  string
	Value []byte
}

type xrayUser struct {
	Level   uint32
	Email   string
	Account typedMessage
}

type inboundUser struct {
	Username string
	UUID     string
	Password string
	Flow     string
}

func walkFields(data []byte, fn func(num protowire.Number, wt protowire.Type, v uint64, b []byte) error) error {
	for len(data) > 0 {
		num, wt, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		var v uint64
		var b []byte
		switch wt {
		case protowire.VarintType:
			v, n = protowire.ConsumeVarint(data)
		case protowire.BytesType:
			b, n = protowire.ConsumeBytes(data)
		case protowire.Fixed32Type:
			f, cn := protowire.ConsumeFixed32(data)
			v, n = uint64(f), cn
		case protowire.Fixed64Type:
			v, n = protowire.ConsumeFixed64(data)
		default:
			return fmt.Errorf("unsupported wire type %d", wt)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		if err := fn(num, wt, v, b); err != nil {
			return err
		}
	}
	return nil
}

func appendString(b []byte, num protowire.Number, s string) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendString(b, s)
}

func appendBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func appendVarint(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func appendMessage(b []byte, num protowire.Number, inner []byte) []byte {
	return appendBytes(b, num, inner)
}

// --- proxyman.command ---

func decodeAlterInbound(data []byte) (tag string, op typedMessage, err error) {
	err = walkFields(data, func(num protowire.Number, wt protowire.Type, _ uint64, b []byte) error {
		switch num {
		case 1:
			tag = string(b)
		case 2:
			op, _ = decodeTypedMessage(b)
		}
		return nil
	})
	return
}

func decodeTypedMessage(data []byte) (typedMessage, error) {
	var tm typedMessage
	err := walkFields(data, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		switch num {
		case 1:
			tm.Type = string(b)
		case 2:
			tm.Value = append([]byte(nil), b...)
		}
		return nil
	})
	return tm, err
}

func decodeUser(data []byte) (xrayUser, error) {
	var user xrayUser
	err := walkFields(data, func(num protowire.Number, wt protowire.Type, v uint64, b []byte) error {
		switch num {
		case 1:
			user.Level = uint32(v)
		case 2:
			user.Email = string(b)
		case 3:
			user.Account, _ = decodeTypedMessage(b)
		}
		return nil
	})
	return user, err
}

func decodeAddUserOperation(data []byte) (xrayUser, error) {
	var user xrayUser
	err := walkFields(data, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num == 1 {
			user, _ = decodeUser(b)
		}
		return nil
	})
	return user, err
}

func decodeRemoveUserOperation(data []byte) (email string, err error) {
	err = walkFields(data, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num == 1 {
			email = string(b)
		}
		return nil
	})
	return
}

func accountUser(tm typedMessage) (inboundUser, error) {
	switch tm.Type {
	case "xray.proxy.vless.Account":
		var user inboundUser
		err := walkFields(tm.Value, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
			switch num {
			case 1:
				user.UUID = string(b)
			case 2:
				user.Flow = string(b)
			}
			return nil
		})
		return user, err
	case "xray.proxy.vmess.Account":
		var user inboundUser
		err := walkFields(tm.Value, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
			if num == 1 {
				user.UUID = string(b)
			}
			return nil
		})
		return user, err
	case "xray.proxy.trojan.Account", "xray.proxy.shadowsocks.Account":
		var user inboundUser
		err := walkFields(tm.Value, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
			if num == 1 {
				user.Password = string(b)
			}
			return nil
		})
		return user, err
	default:
		return inboundUser{}, fmt.Errorf("unsupported account type %q", tm.Type)
	}
}

func encodeVLESSAccount(uuid, flow string) []byte {
	var account []byte
	account = appendString(account, 1, uuid)
	if flow != "" {
		account = appendString(account, 2, flow)
	}
	return account
}

func encodeUser(email, uuid, flow string) []byte {
	account := typedMessage{Type: "xray.proxy.vless.Account", Value: encodeVLESSAccount(uuid, flow)}
	var accountMsg []byte
	accountMsg = appendString(accountMsg, 1, account.Type)
	accountMsg = appendBytes(accountMsg, 2, account.Value)

	var user []byte
	user = appendString(user, 2, email)
	user = appendMessage(user, 3, accountMsg)
	return user
}

func encodeInboundConfig(tag string) []byte {
	return appendString(nil, 1, tag)
}

// --- stats.command ---

func decodeGetStats(data []byte) (name string, reset bool, err error) {
	err = walkFields(data, func(num protowire.Number, wt protowire.Type, v uint64, b []byte) error {
		switch num {
		case 1:
			name = string(b)
		case 2:
			reset = v != 0
		}
		return nil
	})
	return
}

func decodeQueryStats(data []byte) (pattern string, reset bool, err error) {
	return decodeGetStats(data)
}

func encodeStat(name string, value int64) []byte {
	var stat []byte
	stat = appendString(stat, 1, name)
	stat = appendVarint(stat, 2, uint64(value))
	return stat
}

type statPair struct {
	Name  string
	Value int64
}

func encodeStatsResponse(stats []statPair) []byte {
	var out []byte
	for _, stat := range stats {
		out = appendMessage(out, 1, encodeStat(stat.Name, stat.Value))
	}
	return out
}

func encodeSysStats(uptime uint32) []byte {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	var out []byte
	out = appendVarint(out, 1, uint64(runtime.NumGoroutine()))
	out = appendVarint(out, 2, uint64(m.NumGC))
	out = appendVarint(out, 3, m.Alloc)
	out = appendVarint(out, 4, m.TotalAlloc)
	out = appendVarint(out, 5, m.Sys)
	out = appendVarint(out, 6, m.Mallocs)
	out = appendVarint(out, 7, m.Frees)
	out = appendVarint(out, 8, m.HeapObjects)
	out = appendVarint(out, 9, m.PauseTotalNs)
	out = appendVarint(out, 10, uint64(uptime))
	return out
}

func encodeOnlineIPList(name string) []byte {
	return appendString(nil, 1, name)
}

func encodeAllOnlineUsers(users []string) []byte {
	var out []byte
	for _, user := range users {
		out = appendString(out, 1, user)
	}
	return out
}

func encodeUsersStats(users []userTraffic, includeTraffic bool) []byte {
	var out []byte
	for _, user := range users {
		var stat []byte
		stat = appendString(stat, 1, user.Email)
		if includeTraffic {
			var traffic []byte
			traffic = appendVarint(traffic, 1, uint64(user.Upload))
			traffic = appendVarint(traffic, 2, uint64(user.Download))
			stat = appendMessage(stat, 3, traffic)
		}
		out = appendMessage(out, 1, stat)
	}
	return out
}

type userTraffic struct {
	Email    string
	Upload   int64
	Download int64
}
