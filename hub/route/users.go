package route

import (
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// trafficUsers returns the per-user traffic counters of the inbounds:
//
//	GET /traffic/users?inbound=&user=&reset=true
//
// The counters are payload bytes on the outbound side. With reset=true the
// traffic fields restart from zero atomically with the read, the analogue of
// Xray's QueryStats reset.
func trafficUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	render.JSON(w, r, statistic.DefaultUserManager.Snapshot(
		query.Get("inbound"),
		query.Get("user"),
		query.Get("reset") == "true",
	))
}
