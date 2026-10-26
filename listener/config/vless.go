package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
)

type VlessUser struct {
	Username string
	UUID     string
	Flow     string
}

type VlessServer struct {
	Enable          bool
	Listen          string
	Users           []VlessUser
	Decryption      string
	WsPath          string
	XHTTPConfig     XHTTPConfig
	XDriveConfig    XDriveConfig
	GrpcServiceName string
	Certificate     string
	PrivateKey      string
	ClientAuthType  string
	ClientAuthCert  string
	EchKey          string
	AllowInsecure   bool
	ShadowTLS       ShadowTLS      `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS          ResTLS         `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig       JLSConfig      `yaml:"jls-config" json:"jls-config,omitempty"`
	RealityConfig   reality.Config `yaml:"reality-config" json:"reality-config,omitempty"`
	MuxOption       sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
}

type XHTTPConfig struct {
	Path                 string
	Host                 string
	Mode                 string
	XPaddingBytes        string
	XPaddingObfsMode     bool
	XPaddingKey          string
	XPaddingHeader       string
	XPaddingPlacement    string
	XPaddingMethod       string
	UplinkHTTPMethod     string
	SessionPlacement     string
	SessionKey           string
	SeqPlacement         string
	SeqKey               string
	UplinkDataPlacement  string
	UplinkDataKey        string
	UplinkChunkSize      string
	NoSSEHeader          bool
	ScStreamUpServerSecs string
	ScMaxBufferedPosts   string
	ScMaxEachPostBytes   string
}

// XDriveConfig is the runtime form of the xdrive inbound transport: the
// segments live in a cloud folder, the listener opens no TCP socket.
type XDriveConfig struct {
	Service           string
	RemoteFolder      string
	Secrets           []string
	Template          string
	SegmentBytes      int
	FlushIntervalMs   int
	PollIntervalMs    int
	MaxPollIntervalMs int
	EagerWindowMs     int
	HoleTimeoutMs     int
	SessionTTLSeconds int
	Concurrency       int
}

func (t VlessServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
