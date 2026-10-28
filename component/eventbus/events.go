package eventbus

// Payloads of the events (Event.Data).

// States of a user.session event.
const (
	SessionOnline  = "online"
	SessionOffline = "offline"
)

// UserSession is the data of a user.session event: the user of an inbound
// opened its first tracked connection (online) or closed its last one
// (offline). The events of one user are published by the goroutines of its
// connections, so an online and an offline that happen at the same moment
// may arrive in either order: the connection count of GET /traffic/users is
// the state, the events are the hint to read it.
type UserSession struct {
	Inbound string `json:"inbound"`
	User    string `json:"user"`
	State   string `json:"state"`
	// Remote is the client address of the connection that brought the user
	// online, without the port.
	Remote string `json:"remote,omitempty"`
}

// UserLimit is the data of a user.limit event.
type UserLimit struct {
	Inbound string `json:"inbound"`
	User    string `json:"user"`
	// Reason is "quota", "expired" or "max-conns".
	Reason string `json:"reason"`
	// Action is "closed" (the quota was used up or the user expired: its
	// connections are closed) or "rejected" (a new connection was refused).
	Action string `json:"action"`
	// Suppressed is the number of rejections of the user not reported since
	// the previous rejected event (a user is reported at most once a second).
	Suppressed int64 `json:"suppressed,omitempty"`
}

// Actions of a user.limit event.
const (
	LimitClosed   = "closed"
	LimitRejected = "rejected"
)

// UserRevoked is the data of a user.revoked event: users removed from the
// runtime table of an inbound or re-keyed in it (REST /inbounds, Xray
// AlterInbound), whose open connections were closed.
type UserRevoked struct {
	Inbound string   `json:"inbound"`
	Users   []string `json:"users"`
	// Closed is the number of tracked connections closed.
	Closed int `json:"closed"`
}

// Status values of config.reload.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// ConfigReload is the data of a config.reload event.
type ConfigReload struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Dropped is the data of a dropped event.
type Dropped struct {
	Count uint64 `json:"count"`
}

// PublishConfigReload reports the result of a configuration reload.
func PublishConfigReload(err error) {
	if !Enabled(TypeConfigReload) {
		return
	}
	d := ConfigReload{Status: StatusOK}
	if err != nil {
		d = ConfigReload{Status: StatusError, Error: err.Error()}
	}
	Publish(TypeConfigReload, d)
}
