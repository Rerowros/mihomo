package xdrive

import (
	"encoding/json"
	"strconv"
	"strings"
)

// jsonString returns the string at a dotted path of a JSON document, e.g.
// "token.access_token" or "items.0.href".
func jsonString(payload []byte, path string) string {
	value := jsonValue(payload, path)
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// jsonNumber returns the number at a dotted path, or 0.
func jsonNumber(payload []byte, path string) int64 {
	value := jsonValue(payload, path)
	switch v := value.(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

func jsonValue(payload []byte, path string) interface{} {
	var document interface{}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil {
		return nil
	}
	for _, part := range strings.Split(path, ".") {
		switch node := document.(type) {
		case map[string]interface{}:
			document = node[part]
		case []interface{}:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return nil
			}
			document = node[index]
		default:
			return nil
		}
	}
	return document
}
