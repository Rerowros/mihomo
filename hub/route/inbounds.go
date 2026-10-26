package route

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// inboundRouter manages the runtime users of the inbound listeners:
//
//	GET    /inbounds
//	GET    /inbounds/{name}
//	GET    /inbounds/{name}/users
//	PUT    /inbounds/{name}/users            {"users":[...]}  replace all
//	POST   /inbounds/{name}/users            {user}            add one
//	PATCH  /inbounds/{name}/users/{user}     {user}            modify one
//	DELETE /inbounds/{name}/users/{user}                       remove one
func inboundRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", listInbounds)
	r.Route("/{name}", func(r chi.Router) {
		r.Get("/", getInbound)
		r.Get("/users", getInboundUsers)
		r.Put("/users", putInboundUsers)
		r.Post("/users", postInboundUser)
		r.Patch("/users/{user}", patchInboundUser)
		r.Delete("/users/{user}", deleteInboundUser)
	})
	return r
}

func listInbounds(w http.ResponseWriter, r *http.Request) {
	names := listener.InboundListenerNames()
	inbounds := make([]render.M, 0, len(names))
	for _, name := range names {
		inbound, _ := listener.GetInboundListener(name)
		users, _ := listener.GetInboundUsers(name)
		inbounds = append(inbounds, render.M{
			"name":    name,
			"address": inbound.Address(),
			"users":   len(users),
		})
	}
	render.JSON(w, r, render.M{"inbounds": inbounds})
}

func getInbound(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	inbound, ok := listener.GetInboundListener(name)
	if !ok {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError(C.ErrInboundNotFound.Error()))
		return
	}
	users, err := listener.GetInboundUsers(name)
	if err != nil && !errors.Is(err, C.ErrInboundNoUserTable) {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.JSON(w, r, render.M{
		"name":    name,
		"address": inbound.Address(),
		"users":   users,
	})
}

func getInboundUsers(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	users, err := listener.GetInboundUsers(name)
	if err != nil {
		writeInboundUserError(w, r, err)
		return
	}
	render.JSON(w, r, render.M{"inbound": name, "users": users})
}

type inboundUsersPayload struct {
	Users []C.InboundUser `json:"users"`
}

func putInboundUsers(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	var payload inboundUsersPayload
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	var removed []string
	err := listener.UpdateInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		for _, old := range users {
			kept := false
			for _, next := range payload.Users {
				if next.Username == old.Username {
					kept = true
					break
				}
			}
			if !kept {
				removed = append(removed, old.Username)
			}
		}
		return payload.Users, nil
	})
	if err != nil {
		writeInboundUserError(w, r, err)
		return
	}
	for _, user := range removed {
		statistic.DefaultManager.CloseByUser(name, user)
	}
	render.NoContent(w, r)
}

func postInboundUser(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	var user C.InboundUser
	if err := render.DecodeJSON(r.Body, &user); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	err := listener.UpdateInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		for _, existing := range users {
			if existing.Username == user.Username {
				return nil, C.ErrInboundUserExists
			}
		}
		return append(users, user), nil
	})
	if err != nil {
		writeInboundUserError(w, r, err)
		return
	}
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, user)
}

func patchInboundUser(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	username := getEscapeParam(r, "user")
	var patch C.InboundUser
	if err := render.DecodeJSON(r.Body, &patch); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	err := listener.UpdateInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		found := false
		for i := range users {
			if users[i].Username != username {
				continue
			}
			found = true
			if patch.Username != "" {
				users[i].Username = patch.Username
			}
			if patch.UUID != "" {
				users[i].UUID = patch.UUID
			}
			if patch.Password != "" {
				users[i].Password = patch.Password
			}
			if patch.Flow != "" {
				users[i].Flow = patch.Flow
			}
			if patch.AlterID != 0 {
				users[i].AlterID = patch.AlterID
			}
		}
		if !found {
			return nil, C.ErrInboundUserNotFound
		}
		return users, nil
	})
	if err != nil {
		writeInboundUserError(w, r, err)
		return
	}
	// A re-keyed user's existing sessions still carry the old credentials;
	// close them so the change takes effect at once.
	closed := statistic.DefaultManager.CloseByUser(name, username)
	render.JSON(w, r, render.M{"closed": closed})
}

func deleteInboundUser(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	username := getEscapeParam(r, "user")
	err := listener.UpdateInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		kept := make([]C.InboundUser, 0, len(users))
		found := false
		for _, user := range users {
			if user.Username == username {
				found = true
				continue
			}
			kept = append(kept, user)
		}
		if !found {
			return nil, C.ErrInboundUserNotFound
		}
		return kept, nil
	})
	if err != nil {
		writeInboundUserError(w, r, err)
		return
	}
	closed := statistic.DefaultManager.CloseByUser(name, username)
	render.JSON(w, r, render.M{"closed": closed})
}

func writeInboundUserError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, C.ErrInboundNotFound):
		status = http.StatusNotFound
	case errors.Is(err, C.ErrInboundNoUserTable), errors.Is(err, C.ErrInboundUserExists):
		status = http.StatusConflict
	case errors.Is(err, C.ErrInboundUserNotFound):
		status = http.StatusNotFound
	case errors.Is(err, C.ErrInvalidInboundUser):
		status = http.StatusBadRequest
	}
	render.Status(r, status)
	render.JSON(w, r, newError(err.Error()))
}
