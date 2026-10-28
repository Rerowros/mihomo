package constant

import (
	"errors"
	"io"
)

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
	SetUsers(users []InboundUser) (InboundUserChange, error)
}

// InboundUserChange reports what a user table update revoked: the names whose
// record was removed or replaced, and how many tracked connections it closed.
type InboundUserChange struct {
	Revoked []string
	Closed  int
}

// InboundSession is the record of the user that authenticated a connection.
// It travels with the connection (Metadata.InSession), so the tunnel can drop
// traffic of a revoked user and bind its trackers to the record.
type InboundSession interface {
	// Revoked reports whether the user was removed or re-keyed.
	Revoked() bool
	// Bind registers c to be closed when the record is revoked. ok is false
	// when it is already revoked: the caller must drop c. release unregisters
	// c and is safe to call more than once; it is never nil.
	Bind(c io.Closer, tracked bool) (release func(), ok bool)
}

var (
	ErrInboundNotFound     = errors.New("inbound not found")
	ErrInboundNoUserTable  = errors.New("inbound does not support runtime users")
	ErrInboundUserNotFound = errors.New("inbound user not found")
	ErrInboundUserExists   = errors.New("inbound user already exists")
	ErrInvalidInboundUser  = errors.New("invalid inbound user")
	ErrInboundUserRevoked  = errors.New("inbound user removed")
)
