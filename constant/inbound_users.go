package constant

import "errors"

// InboundUser is one user of an inbound listener, in the shape the controller
// and the Xray-compatible API exchange. A listener uses the fields its
// protocol needs: VLESS/VMess take UUID (and Flow/AlterID), Trojan/AnyTLS/
// TUIC/Hysteria2 take Password.
type InboundUser struct {
	Username string `json:"username"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Flow     string `json:"flow,omitempty"`
	AlterID  int    `json:"alterId,omitempty"`
}

// InboundUserManager is implemented by user-aware inbound listeners whose user
// table can be replaced at runtime.
type InboundUserManager interface {
	GetUsers() []InboundUser
	SetUsers(users []InboundUser) error
}

var (
	ErrInboundNotFound     = errors.New("inbound not found")
	ErrInboundNoUserTable  = errors.New("inbound does not support runtime users")
	ErrInboundUserNotFound = errors.New("inbound user not found")
	ErrInboundUserExists   = errors.New("inbound user already exists")
	ErrInvalidInboundUser  = errors.New("invalid inbound user")
)
