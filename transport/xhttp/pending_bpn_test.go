package xhttp

import (
	"fmt"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sessions that never start a download are capped, so a probe flood cannot
// allocate them without bound.
func TestServerPendingSessionCap(t *testing.T) {
	previous := maxPendingSessions
	maxPendingSessions = 2
	t.Cleanup(func() { maxPendingSessions = previous })

	handler, err := NewServerHandler(ServerOption{
		Config:      Config{Path: "/xhttp", Mode: "packet-up", XPaddingBytes: "1-1"},
		ConnHandler: func(net.Conn) {},
	})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("http://example.com/xhttp/session-%d/0?x_padding=x", i), http.NoBody)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		t.Logf("session %d: %d %s", i, recorder.Code, recorder.Body.String())
		if i < 2 {
			assert.Equal(t, http.StatusOK, recorder.Code, "session %d", i)
		} else {
			assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "session %d", i)
		}
	}
}
