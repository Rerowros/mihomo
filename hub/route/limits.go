package route

import (
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// limitRouter manages per-user quotas and speed limits:
//
//	GET    /limits/users?inbound=&user=
//	PUT    /limits/users            {"limits":[...]}   replace all
//	POST   /limits/users            {limit}             add or update one
//	DELETE /limits/users?inbound=&user=
//	POST   /limits/users/reset-quota?inbound=&user=
func limitRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/users", getLimits)
	r.Put("/users", putLimits)
	r.Post("/users", postLimit)
	r.Delete("/users", deleteLimit)
	r.Post("/users/reset-quota", resetLimitQuota)
	return r
}

func getLimits(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	render.JSON(w, r, statistic.DefaultLimitManager.Snapshot(query.Get("inbound"), query.Get("user")))
}

type limitsPayload struct {
	Limits []statistic.UserLimit `json:"limits"`
}

func putLimits(w http.ResponseWriter, r *http.Request) {
	var payload limitsPayload
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	statistic.DefaultLimitManager.Replace(payload.Limits)
	render.JSON(w, r, statistic.DefaultLimitManager.Snapshot("", ""))
}

func postLimit(w http.ResponseWriter, r *http.Request) {
	var limit statistic.UserLimit
	if err := render.DecodeJSON(r.Body, &limit); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if limit.Inbound == "" || limit.User == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("inbound and user are required"))
		return
	}
	statistic.DefaultLimitManager.Set(limit)
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, statistic.DefaultLimitManager.Snapshot(limit.Inbound, limit.User))
}

func deleteLimit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if !statistic.DefaultLimitManager.Delete(query.Get("inbound"), query.Get("user")) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("limit not found"))
		return
	}
	render.NoContent(w, r)
}

func resetLimitQuota(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if !statistic.DefaultLimitManager.ResetQuota(query.Get("inbound"), query.Get("user")) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("limit not found"))
		return
	}
	render.JSON(w, r, statistic.DefaultLimitManager.Snapshot(query.Get("inbound"), query.Get("user")))
}
