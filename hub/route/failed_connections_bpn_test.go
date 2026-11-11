package route

import (
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
)

type failedConnWire struct {
	ID       string   `json:"id"`
	Metadata struct {
		Network string `json:"network"`
		Host    string `json:"host"`
		DstPort string `json:"destinationPort"`
		Process string `json:"process"`
	} `json:"metadata"`
	Chains     []string `json:"chains"`
	Rule       string   `json:"rule"`
	RulePayload string  `json:"rulePayload"`
	Error      string   `json:"error"`
	DurationMs int64    `json:"durationMs"`
}

type failedSnapWire struct {
	FailedTotal int64            `json:"failedTotal"`
	Connections []failedConnWire `json:"connections"`
}

type mainSnapWire struct {
	FailedTotal       int64            `json:"failedTotal"`
	FailedConnections []failedConnWire `json:"failedConnections"`
}

func TestBPNFailedConnectionsEndpoints(t *testing.T) {
	statistic.DefaultManager.ResetStatistic()
	t.Cleanup(func() {
		statistic.DefaultManager.ResetStatistic()
	})

	md := &C.Metadata{
		NetWork: C.TCP,
		Host:    "blocked.example.org",
		DstPort: 443,
		SrcIP:   netip.MustParseAddr("198.18.0.1"),
		SrcPort: 54321,
		Process: "browser.exe",
		InUser:  "private-user-token",
	}
	fc := statistic.NewFailedConnection(
		md,
		time.Now(),
		C.Chain{"de-exit", "VPN"},
		C.Chain{"", ""},
		nil,
		errors.New("i/o timeout"),
		320*time.Millisecond,
	)
	fc.Rule = "DOMAIN-SUFFIX"
	fc.RulePayload = "example.org"
	statistic.DefaultManager.RecordFailed(fc)

	r := router(false, "s3cr3t", "", Cors{})

	// Unauthenticated request is rejected.
	unauthReq := httptest.NewRequest(http.MethodGet, "/connections/failed", nil)
	unauthRec := httptest.NewRecorder()
	r.ServeHTTP(unauthRec, unauthReq)
	require.Equal(t, http.StatusUnauthorized, unauthRec.Code)

	// Authenticated GET /connections/failed returns wire-compatible JSON with InUser redacted.
	req := httptest.NewRequest(http.MethodGet, "/connections/failed?limit=10", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "private-user-token")

	var failedSnap failedSnapWire
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &failedSnap))
	require.Equal(t, int64(1), failedSnap.FailedTotal)
	require.Len(t, failedSnap.Connections, 1)
	require.Equal(t, "tcp", failedSnap.Connections[0].Metadata.Network)
	require.Equal(t, "blocked.example.org", failedSnap.Connections[0].Metadata.Host)
	require.Equal(t, "443", failedSnap.Connections[0].Metadata.DstPort)
	require.Equal(t, []string{"de-exit", "VPN"}, failedSnap.Connections[0].Chains)
	require.Contains(t, failedSnap.Connections[0].Error, "i/o timeout")
	require.Equal(t, int64(320), failedSnap.Connections[0].DurationMs)

	// GET /connections also includes failedTotal and failedConnections.
	connReq := httptest.NewRequest(http.MethodGet, "/connections", nil)
	connReq.Header.Set("Authorization", "Bearer s3cr3t")
	connRec := httptest.NewRecorder()
	r.ServeHTTP(connRec, connReq)
	require.Equal(t, http.StatusOK, connRec.Code)

	var mainSnap mainSnapWire
	require.NoError(t, json.Unmarshal(connRec.Body.Bytes(), &mainSnap))
	require.Equal(t, int64(1), mainSnap.FailedTotal)
	require.Len(t, mainSnap.FailedConnections, 1)

	// DELETE /connections/failed clears the ring buffer (and is not mistaken for /{id}).
	delReq := httptest.NewRequest(http.MethodDelete, "/connections/failed", nil)
	delReq.Header.Set("Authorization", "Bearer s3cr3t")
	delRec := httptest.NewRecorder()
	r.ServeHTTP(delRec, delReq)
	require.Equal(t, http.StatusNoContent, delRec.Code)

	req2 := httptest.NewRequest(http.MethodGet, "/connections/failed", nil)
	req2.Header.Set("Authorization", "Bearer s3cr3t")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &failedSnap))
	require.Empty(t, failedSnap.Connections)
	require.Equal(t, int64(1), failedSnap.FailedTotal)
}
