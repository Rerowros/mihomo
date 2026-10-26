package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vless"

	"github.com/gofrs/uuid/v5"
)

type VlessOption struct {
	BaseOption
	Users           []VlessUser   `inbound:"users"`
	Decryption      string        `inbound:"decryption,omitempty"`
	WsPath          string        `inbound:"ws-path,omitempty"`
	XHTTPConfig     XHTTPConfig   `inbound:"xhttp-config,omitempty"`
	XDriveConfig    XDriveConfig  `inbound:"xdrive-config,omitempty"`
	GrpcServiceName string        `inbound:"grpc-service-name,omitempty"`
	Certificate     string        `inbound:"certificate,omitempty"`
	PrivateKey      string        `inbound:"private-key,omitempty"`
	ClientAuthType  string        `inbound:"client-auth-type,omitempty"`
	ClientAuthCert  string        `inbound:"client-auth-cert,omitempty"`
	EchKey          string        `inbound:"ech-key,omitempty"`
	AllowInsecure   bool          `inbound:"allow-insecure,omitempty"`
	ShadowTLS       ShadowTLS     `inbound:"shadow-tls,omitempty"`
	ResTLS          ResTLS        `inbound:"res-tls,omitempty"`
	JLSConfig       JLSConfig     `inbound:"jls-config,omitempty"`
	RealityConfig   RealityConfig `inbound:"reality-config,omitempty"`
	MuxOption       MuxOption     `inbound:"mux-option,omitempty"`
}

type VlessUser struct {
	Username string `inbound:"username,omitempty"`
	UUID     string `inbound:"uuid"`
	Flow     string `inbound:"flow,omitempty"`
}

type XHTTPConfig struct {
	Path                 string `inbound:"path,omitempty"`
	Host                 string `inbound:"host,omitempty"`
	Mode                 string `inbound:"mode,omitempty"`
	XPaddingBytes        string `inbound:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool   `inbound:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string `inbound:"x-padding-key,omitempty"`
	XPaddingHeader       string `inbound:"x-padding-header,omitempty"`
	XPaddingPlacement    string `inbound:"x-padding-placement,omitempty"`
	XPaddingMethod       string `inbound:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string `inbound:"uplink-http-method,omitempty"`
	SessionPlacement     string `inbound:"session-placement,omitempty"`
	SessionKey           string `inbound:"session-key,omitempty"`
	SeqPlacement         string `inbound:"seq-placement,omitempty"`
	SeqKey               string `inbound:"seq-key,omitempty"`
	UplinkDataPlacement  string `inbound:"uplink-data-placement,omitempty"`
	UplinkDataKey        string `inbound:"uplink-data-key,omitempty"`
	UplinkChunkSize      string `inbound:"uplink-chunk-size,omitempty"`
	NoSSEHeader          bool   `inbound:"no-sse-header,omitempty"`
	ScStreamUpServerSecs string `inbound:"sc-stream-up-server-secs,omitempty"`
	ScMaxBufferedPosts   string `inbound:"sc-max-buffered-posts,omitempty"`
	ScMaxEachPostBytes   string `inbound:"sc-max-each-post-bytes,omitempty"`
}

// XDriveConfig is the inbound form of XDriveOptions. The inbound has no
// listening port: it polls the session directory of the storage.
type XDriveConfig struct {
	Service           string   `inbound:"service"`
	RemoteFolder      string   `inbound:"remote-folder"`
	Secrets           []string `inbound:"secrets,omitempty"`
	Template          string   `inbound:"template,omitempty"`
	SegmentBytes      int      `inbound:"segment-bytes,omitempty"`
	FlushIntervalMs   int      `inbound:"flush-interval-ms,omitempty"`
	PollIntervalMs    int      `inbound:"poll-interval-ms,omitempty"`
	MaxPollIntervalMs int      `inbound:"max-poll-interval-ms,omitempty"`
	EagerWindowMs     int      `inbound:"eager-window-ms,omitempty"`
	HoleTimeoutMs     int      `inbound:"hole-timeout-ms,omitempty"`
	SessionTTLSeconds int      `inbound:"session-ttl-seconds,omitempty"`
	Concurrency       int      `inbound:"concurrency,omitempty"`
}

func (o XDriveConfig) Build() LC.XDriveConfig {
	return LC.XDriveConfig{
		Service:           o.Service,
		RemoteFolder:      o.RemoteFolder,
		Secrets:           o.Secrets,
		Template:          o.Template,
		SegmentBytes:      o.SegmentBytes,
		FlushIntervalMs:   o.FlushIntervalMs,
		PollIntervalMs:    o.PollIntervalMs,
		MaxPollIntervalMs: o.MaxPollIntervalMs,
		EagerWindowMs:     o.EagerWindowMs,
		HoleTimeoutMs:     o.HoleTimeoutMs,
		SessionTTLSeconds: o.SessionTTLSeconds,
		Concurrency:       o.Concurrency,
	}
}

func (o XHTTPConfig) Build() LC.XHTTPConfig {
	return LC.XHTTPConfig{
		Path:                 o.Path,
		Host:                 o.Host,
		Mode:                 o.Mode,
		NoSSEHeader:          o.NoSSEHeader,
		XPaddingBytes:        o.XPaddingBytes,
		XPaddingObfsMode:     o.XPaddingObfsMode,
		XPaddingKey:          o.XPaddingKey,
		XPaddingHeader:       o.XPaddingHeader,
		XPaddingPlacement:    o.XPaddingPlacement,
		XPaddingMethod:       o.XPaddingMethod,
		UplinkHTTPMethod:     o.UplinkHTTPMethod,
		SessionPlacement:     o.SessionPlacement,
		SessionKey:           o.SessionKey,
		SeqPlacement:         o.SeqPlacement,
		SeqKey:               o.SeqKey,
		UplinkDataPlacement:  o.UplinkDataPlacement,
		UplinkDataKey:        o.UplinkDataKey,
		UplinkChunkSize:      o.UplinkChunkSize,
		ScStreamUpServerSecs: o.ScStreamUpServerSecs,
		ScMaxBufferedPosts:   o.ScMaxBufferedPosts,
		ScMaxEachPostBytes:   o.ScMaxEachPostBytes,
	}
}

func (o VlessOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Vless struct {
	*Base
	config *VlessOption
	l      C.MultiAddrListener
	svc    *sing_vless.Listener
	vs     LC.VlessServer
}

func NewVless(options *VlessOption) (*Vless, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users := make([]LC.VlessUser, len(options.Users))
	for i, v := range options.Users {
		users[i] = LC.VlessUser{
			Username: v.Username,
			UUID:     v.UUID,
			Flow:     v.Flow,
		}
	}
	return &Vless{
		Base:   base,
		config: options,
		vs: LC.VlessServer{
			Enable:          true,
			Listen:          base.RawAddress(),
			Users:           users,
			Decryption:      options.Decryption,
			WsPath:          options.WsPath,
			XHTTPConfig:     options.XHTTPConfig.Build(),
			XDriveConfig:    options.XDriveConfig.Build(),
			GrpcServiceName: options.GrpcServiceName,
			Certificate:     options.Certificate,
			PrivateKey:      options.PrivateKey,
			ClientAuthType:  options.ClientAuthType,
			ClientAuthCert:  options.ClientAuthCert,
			EchKey:          options.EchKey,
			AllowInsecure:   options.AllowInsecure,
			ShadowTLS:       options.ShadowTLS.Build(),
			ResTLS:          options.ResTLS.Build(),
			JLSConfig:       options.JLSConfig.Build(),
			RealityConfig:   options.RealityConfig.Build(),
			MuxOption:       options.MuxOption.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *Vless) Config() C.InboundConfig {
	return v.config
}

// Address implements constant.InboundListener
func (v *Vless) Address() string {
	if v.config.XDriveConfig.Service != "" {
		return "xdrive:" + v.config.XDriveConfig.Service
	}
	var addrList []string
	if v.l != nil {
		for _, addr := range v.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (v *Vless) Listen(tunnel C.Tunnel) error {
	var err error
	v.svc, err = sing_vless.New(v.vs, v.ListenConfig(), tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	v.l = v.svc
	log.Infoln("Vless[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// GetUsers implements constant.InboundUserManager.
func (v *Vless) GetUsers() []C.InboundUser {
	var users []LC.VlessUser
	if v.svc != nil {
		users = v.svc.Users()
	} else {
		users = v.vs.Users
	}
	result := make([]C.InboundUser, 0, len(users))
	for _, user := range users {
		result = append(result, C.InboundUser{
			Username: user.Username,
			UUID:     user.UUID,
			Flow:     user.Flow,
		})
	}
	return result
}

// SetUsers implements constant.InboundUserManager: the new table takes effect
// for the next handshake without restarting the listener.
func (v *Vless) SetUsers(users []C.InboundUser) error {
	if v.svc == nil {
		return C.ErrInboundNotFound
	}
	converted := make([]LC.VlessUser, 0, len(users))
	seenNames := make(map[string]struct{}, len(users))
	seenUUIDs := make(map[string]struct{}, len(users))
	for _, user := range users {
		if user.Username == "" || user.UUID == "" {
			return C.ErrInvalidInboundUser
		}
		if _, err := uuid.FromString(user.UUID); err != nil {
			return C.ErrInvalidInboundUser
		}
		if user.Flow != "" && user.Flow != vless.XRV {
			return C.ErrInvalidInboundUser
		}
		if _, ok := seenNames[user.Username]; ok {
			return C.ErrInvalidInboundUser
		}
		if _, ok := seenUUIDs[user.UUID]; ok {
			return C.ErrInvalidInboundUser
		}
		seenNames[user.Username] = struct{}{}
		seenUUIDs[user.UUID] = struct{}{}
		converted = append(converted, LC.VlessUser{
			Username: user.Username,
			UUID:     user.UUID,
			Flow:     user.Flow,
		})
	}
	v.svc.UpdateUsers(converted)
	return nil
}

// Close implements constant.InboundListener
func (v *Vless) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*Vless)(nil)
