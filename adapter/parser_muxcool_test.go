package adapter

import (
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
)

func TestParseProxyMuxCoolConfigurations(t *testing.T) {
	tests := []struct {
		name                    string
		muxCool                 map[string]any
		wantWrapped             bool
		wantMaxConcurrency      int
		wantMaxConnections      int
		wantMaxCarriers         int
		wantXUDPConcurrency     int
		wantXUDPProxyUDP443Mode string
	}{
		{name: "omitted"},
		{name: "disabled", muxCool: map[string]any{"enabled": false}},
		{
			name: "defaults", muxCool: map[string]any{"enabled": true}, wantWrapped: true,
			wantMaxConcurrency: 8, wantMaxConnections: 128, wantXUDPProxyUDP443Mode: "reject",
		},
		{
			name: "custom",
			muxCool: map[string]any{
				"enabled": true, "max-concurrency": 3, "max-connections": 19, "max-carriers": 2,
				"xudp-concurrency": 4, "xudp-proxy-udp443": "allow",
			},
			wantWrapped: true, wantMaxConcurrency: 3, wantMaxConnections: 19,
			wantMaxCarriers: 2, wantXUDPConcurrency: 4, wantXUDPProxyUDP443Mode: "allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping := vlessMapping(nil)
			if tt.muxCool != nil {
				mapping["mux.cool"] = tt.muxCool
			}
			parsed, err := ParseProxy(mapping)
			if err != nil {
				t.Fatalf("ParseProxy: %v", err)
			}
			defer parsed.Close()
			wrapped := unwrapAutoClose(t, parsed.Adapter())
			muxCool, ok := wrapped.(*outbound.MuxCool)
			if ok != tt.wantWrapped {
				t.Fatalf("MuxCool wrapper present = %t, want %t (%T)", ok, tt.wantWrapped, wrapped)
			}
			if ok {
				options := muxCool.Options()
				if options.MaxConcurrency != tt.wantMaxConcurrency ||
					options.MaxConnections != tt.wantMaxConnections ||
					options.MaxCarriers != tt.wantMaxCarriers ||
					options.XUDPConcurrency != tt.wantXUDPConcurrency ||
					options.XUDPProxyUDP443 != tt.wantXUDPProxyUDP443Mode {
					t.Fatalf("options = %+v", options)
				}
			}
		})
	}
}

func TestParseProxyRejectsInvalidMuxCoolConfigurations(t *testing.T) {
	tests := []struct {
		name    string
		mapping map[string]any
		match   string
	}{
		{
			name:    "negative concurrency",
			mapping: vlessMapping(map[string]any{"mux.cool": map[string]any{"enabled": true, "max-concurrency": -1}}),
			match:   "max-concurrency",
		},
		{
			name:    "negative connections",
			mapping: vlessMapping(map[string]any{"mux.cool": map[string]any{"enabled": true, "max-connections": -1}}),
			match:   "max-connections",
		},
		{
			name:    "negative carriers",
			mapping: vlessMapping(map[string]any{"mux.cool": map[string]any{"enabled": true, "max-carriers": -1}}),
			match:   "max-carriers",
		},
		{
			name:    "negative xudp concurrency",
			mapping: vlessMapping(map[string]any{"mux.cool": map[string]any{"enabled": true, "xudp-concurrency": -1}}),
			match:   "xudp-concurrency",
		},
		{
			name:    "unknown udp 443 policy",
			mapping: vlessMapping(map[string]any{"mux.cool": map[string]any{"enabled": true, "xudp-proxy-udp443": "drop"}}),
			match:   "xudp-proxy-udp443",
		},
		{
			name: "smux conflict",
			mapping: vlessMapping(map[string]any{
				"smux":     map[string]any{"enabled": true},
				"mux.cool": map[string]any{"enabled": true},
			}),
			match: "cannot be enabled together",
		},
		{
			name:    "not vless",
			mapping: map[string]any{"name": "test", "type": "direct", "mux.cool": map[string]any{"enabled": true}},
			match:   "only supported for vless",
		},
		{
			name: "vmess",
			mapping: map[string]any{
				"name": "test", "type": "vmess", "server": "127.0.0.1", "port": 443,
				"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0, "cipher": "auto",
				"mux.cool": map[string]any{"enabled": true},
			},
			match: "only supported for vless",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseProxy(tt.mapping)
			if parsed != nil {
				_ = parsed.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tt.match) {
				t.Fatalf("error = %v, want substring %q", err, tt.match)
			}
		})
	}
}

func vlessMapping(extra map[string]any) map[string]any {
	mapping := map[string]any{
		"name": "vless", "type": "vless", "server": "127.0.0.1", "port": 443,
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tls": true,
	}
	for k, v := range extra {
		mapping[k] = v
	}
	return mapping
}

func TestParseProxyRejectsMuxCoolWithVLESSVision(t *testing.T) {
	for _, flow := range []string{"xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
		t.Run(flow, func(t *testing.T) {
			parsed, err := ParseProxy(vlessMapping(map[string]any{
				"flow":     flow,
				"mux.cool": map[string]any{"enabled": true},
			}))
			if parsed != nil {
				_ = parsed.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "mux.cool cannot be used with VLESS flow") {
				t.Fatalf("error = %v, want mux.cool/flow conflict", err)
			}
		})
	}
}

func TestParseProxyVLESSMuxCoolWrapping(t *testing.T) {
	tests := []struct {
		name        string
		extra       map[string]any
		wantWrapped bool
	}{
		{name: "no key", extra: nil},
		{name: "vision without mux.cool", extra: map[string]any{"flow": "xtls-rprx-vision"}},
		{name: "vision with disabled mux.cool", extra: map[string]any{"flow": "xtls-rprx-vision", "mux.cool": map[string]any{"enabled": false}}},
		{name: "mux.cool without flow", extra: map[string]any{"mux.cool": map[string]any{"enabled": true}}, wantWrapped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseProxy(vlessMapping(tt.extra))
			if err != nil {
				t.Fatalf("ParseProxy: %v", err)
			}
			defer parsed.Close()
			wrapped := unwrapAutoClose(t, parsed.Adapter())
			if _, ok := wrapped.(*outbound.MuxCool); ok != tt.wantWrapped {
				t.Fatalf("MuxCool wrapper present = %t, want %t (%T)", ok, tt.wantWrapped, wrapped)
			}
			if !tt.wantWrapped {
				if _, ok := wrapped.(*outbound.Vless); !ok {
					t.Fatalf("adapter = %T, want *outbound.Vless", wrapped)
				}
			}
		})
	}
}

func unwrapAutoClose(t *testing.T, adapter any) any {
	t.Helper()
	value := reflect.ValueOf(adapter)
	if value.Kind() != reflect.Pointer || value.Elem().Kind() != reflect.Struct {
		t.Fatalf("unexpected outer adapter %T", adapter)
	}
	field := value.Elem().FieldByName("ProxyAdapter")
	if !field.IsValid() || !field.CanInterface() {
		t.Fatalf("cannot unwrap outer adapter %T", adapter)
	}
	return field.Interface()
}
