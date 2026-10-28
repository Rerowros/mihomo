package inbound

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vless"
)

type VlessOption struct {
	BaseOption
	Users           []VlessUser   `inbound:"users"`
	Decryption      string        `inbound:"decryption,omitempty"`
	WsPath          string        `inbound:"ws-path,omitempty"`
	XHTTPConfig     XHTTPConfig   `inbound:"xhttp-config,omitempty"`
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
	if err := checkVlessUsers(users); err != nil {
		return nil, err
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
// for the next handshake without restarting the listener; removed or re-keyed
// users are revoked and their connections closed.
func (v *Vless) SetUsers(users []C.InboundUser) (C.InboundUserChange, error) {
	if v.svc == nil {
		return C.InboundUserChange{}, C.ErrInboundNotFound
	}
	converted := make([]LC.VlessUser, 0, len(users))
	for _, user := range users {
		if user.Username == "" || user.UUID == "" {
			return C.InboundUserChange{}, C.ErrInvalidInboundUser
		}
		if user.Flow != "" && user.Flow != vless.XRV {
			return C.InboundUserChange{}, C.ErrInvalidInboundUser
		}
		converted = append(converted, LC.VlessUser{
			Username: user.Username,
			UUID:     user.UUID,
			Flow:     user.Flow,
		})
	}
	if err := checkVlessUsers(converted); err != nil {
		return C.InboundUserChange{}, err
	}
	return v.svc.UpdateUsers(converted), nil
}

// checkVlessUsers rejects users that would collide in the table: names that
// differ only in case (a panel addresses users by email without case), and ids
// that map to one key. The key is utils.UUIDMap, as in the handshake, so a
// UUID in another case or a string id equal to another user's is caught.
func checkVlessUsers(users []LC.VlessUser) error {
	names := make(map[string]struct{}, len(users))
	keys := make(map[[16]byte]string, len(users))
	for _, user := range users {
		if user.Username != "" {
			name := strings.ToLower(user.Username)
			if _, ok := names[name]; ok {
				return fmt.Errorf("%w: duplicate user name %q", C.ErrInvalidInboundUser, user.Username)
			}
			names[name] = struct{}{}
		}
		key := utils.UUIDMap(user.UUID)
		if other, ok := keys[key]; ok {
			return fmt.Errorf("%w: users %q and %q have the same id", C.ErrInvalidInboundUser, other, user.Username)
		}
		keys[key] = user.Username
	}
	return nil
}

// Close implements constant.InboundListener
func (v *Vless) Close() error {
	return v.l.Close()
}

var _ C.InboundListener = (*Vless)(nil)
