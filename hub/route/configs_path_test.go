package route

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// PUT /configs with a path reads only files below the home directory or
// SAFE_PATHS: a caller of the API must not get the core to parse, and echo
// in its errors, an arbitrary file of the host.
func TestUpdateConfigsRefusesUnsafePath(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("mixed-port: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if C.Path.IsSafePath(outside) {
		t.Skip("the temporary directory is a safe path here (SAFE_PATHS or SKIP_SAFE_PATH_CHECK)")
	}
	for _, path := range []string{outside, "outside.yaml", filepath.Join(C.Path.HomeDir(), "..", "x.yaml")} {
		body := `{"path": ` + strconv.Quote(path) + `}`
		req := httptest.NewRequest(http.MethodPut, "/configs", strings.NewReader(body))
		rec := httptest.NewRecorder()
		updateConfigs(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "path is not") {
			t.Errorf("PUT /configs path %q: got %d %s, want 400 for the path", path, rec.Code, rec.Body.String())
		}
	}
}
