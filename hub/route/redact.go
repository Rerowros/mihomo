package route

import (
	"encoding/json"
	"strings"

	"github.com/metacubex/mihomo/config"
)

// redacted replaces a credential in a controller response.
const redacted = "******"

// redactGeneral removes the credentials of the built-in TUIC, ShadowSocks and VMess
// servers from GET /configs: they are independent of the controller secret
// and would outlive its rotation in the hands of whoever read them. The
// configuration file stays the place to read them.
func redactGeneral(g *config.General) {
	tuic := &g.TuicServer
	if len(tuic.Token) > 0 {
		tokens := make([]string, len(tuic.Token))
		for i := range tokens {
			tokens[i] = redacted
		}
		tuic.Token = tokens
	}
	if len(tuic.Users) > 0 {
		users := make(map[string]string, len(tuic.Users))
		for id := range tuic.Users {
			users[id] = redacted
		}
		tuic.Users = users
	}
	if tuic.PrivateKey != "" {
		tuic.PrivateKey = redacted
	}
	if tuic.EchKey != "" {
		tuic.EchKey = redacted
	}
	g.ShadowSocksConfig = redactJSONString(g.ShadowSocksConfig)
	g.VmessConfig = redactJSONString(g.VmessConfig)
}

// redactJSONString redacts the credentials of a JSON document; a document
// that does not parse is redacted as a whole.
func redactJSONString(s string) string {
	if s == "" {
		return s
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return redacted
	}
	b, err := json.Marshal(redactValue(v, false))
	if err != nil {
		return redacted
	}
	return string(b)
}

func isSecretKey(key string) bool {
	switch strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key)) {
	case "password", "passwd", "psk", "key", "token", "secret", "privatekey", "echkey", "uuid":
		return true
	}
	return false
}

func redactValue(v any, secret bool) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = redactValue(e, secret || isSecretKey(k))
		}
		return v
	case []any:
		for i, e := range v {
			v[i] = redactValue(e, secret)
		}
		return v
	case string:
		if secret && v != "" {
			return redacted
		}
		return v
	default:
		return v
	}
}

// The helpers below undo redactGeneral on PATCH /configs: a client that reads
// GET /configs and sends the document back must not replace the credentials
// with the mask. A masked value keeps the current one; a masked value that has
// no current counterpart is dropped rather than set to the mask.

func restoreTokens(patch, current []string) []string {
	out := make([]string, 0, len(patch))
	for i, token := range patch {
		if token != redacted {
			out = append(out, token)
		} else if i < len(current) {
			out = append(out, current[i])
		}
	}
	return out
}

func restoreUsers(patch, current map[string]string) map[string]string {
	out := make(map[string]string, len(patch))
	for id, password := range patch {
		if password != redacted {
			out[id] = password
		} else if old, ok := current[id]; ok {
			out[id] = old
		}
	}
	return out
}

// restoreJSONString returns the configuration to apply for a redactJSONString
// field: the current one when the patch is the masked current one or a masked
// value cannot be matched, otherwise the patch with the masked values filled
// in from the current document.
func restoreJSONString(patch, current string) string {
	if !strings.Contains(patch, redacted) {
		return patch
	}
	if patch == redactJSONString(current) {
		return current
	}
	var p, c any
	if json.Unmarshal([]byte(patch), &p) != nil || json.Unmarshal([]byte(current), &c) != nil {
		return current
	}
	v, ok := restoreValue(p, c)
	if !ok {
		return current
	}
	b, err := json.Marshal(v)
	if err != nil {
		return current
	}
	return string(b)
}

func restoreValue(p, c any) (any, bool) {
	switch p := p.(type) {
	case map[string]any:
		cm, _ := c.(map[string]any)
		for k, e := range p {
			v, ok := restoreValue(e, cm[k])
			if !ok {
				return nil, false
			}
			p[k] = v
		}
		return p, true
	case []any:
		ca, _ := c.([]any)
		for i, e := range p {
			var ce any
			if i < len(ca) {
				ce = ca[i]
			}
			v, ok := restoreValue(e, ce)
			if !ok {
				return nil, false
			}
			p[i] = v
		}
		return p, true
	case string:
		if p != redacted {
			return p, true
		}
		if cs, ok := c.(string); ok {
			return cs, true
		}
		return nil, false
	default:
		return p, true
	}
}
