package route

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type fakeTracker struct {
	C.Conn
	info   *statistic.TrackerInfo
	closed atomic.Bool
}

func (f *fakeTracker) ID() string                   { return f.info.UUID.String() }
func (f *fakeTracker) Info() *statistic.TrackerInfo { return f.info }
func (f *fakeTracker) Close() error {
	f.closed.Store(true)
	statistic.DefaultManager.Leave(f)
	return nil
}

func joinFakeTracker(inboundName, user string) *fakeTracker {
	tracker := &fakeTracker{info: &statistic.TrackerInfo{
		UUID:     utils.NewUUIDV4(),
		Metadata: &C.Metadata{InName: inboundName, InUser: user},
	}}
	statistic.DefaultManager.Join(tracker)
	return tracker
}

func startRouteVless(t *testing.T, name string, users []inbound.VlessUser) {
	t.Helper()
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: "0"},
		Users:         users,
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener.PatchInboundListeners(map[string]C.InboundListener{name: in}, tunnel.Tunnel, false)
	if _, ok := listener.GetInboundListener(name); !ok {
		t.Fatal("inbound did not start")
	}
	t.Cleanup(func() { _ = in.Close() })
}

func serveInbounds(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	inboundRouter().ServeHTTP(recorder, request)
	var decoded map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder.Code, decoded
}

// A PATCH that changes nothing must not end the user's sessions.
func TestPatchInboundUserWithoutChangeKeepsSessions(t *testing.T) {
	name := "route-patch-noop"
	uuidA := utils.NewUUIDV4().String()
	startRouteVless(t, name, []inbound.VlessUser{{Username: "a", UUID: uuidA}})
	tracker := joinFakeTracker(name, "a")
	defer tracker.Close()

	code, body := serveInbounds(t, http.MethodPatch, "/"+name+"/users/a", `{"uuid":"`+uuidA+`"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if tracker.closed.Load() {
		t.Fatal("PATCH without changes closed the user's session")
	}
	if closed, _ := body["closed"].(float64); closed != 0 {
		t.Fatalf("closed = %v, want 0", body["closed"])
	}
}

// A POST whose name differs only in case is a duplicate (409), not a second user.
func TestPostInboundUserCaseInsensitiveDuplicate(t *testing.T) {
	name := "route-post-case"
	startRouteVless(t, name, []inbound.VlessUser{{Username: "Alice", UUID: utils.NewUUIDV4().String()}})

	code, body := serveInbounds(t, http.MethodPost, "/"+name+"/users", `{"username":"alice","uuid":"`+utils.NewUUIDV4().String()+`"}`)
	if code != http.StatusConflict {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	users, _ := listener.GetInboundUsers(name)
	if len(users) != 1 {
		t.Fatalf("users = %+v", users)
	}
}

// S-3: DELETE finds the user by name without case, like POST.
func TestDeleteInboundUserCaseInsensitive(t *testing.T) {
	name := "route-delete-case"
	startRouteVless(t, name, []inbound.VlessUser{{Username: "alice", UUID: utils.NewUUIDV4().String()}, {Username: "bob", UUID: utils.NewUUIDV4().String()}})

	code, body := serveInbounds(t, http.MethodDelete, "/"+name+"/users/ALICE", "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	users, _ := listener.GetInboundUsers(name)
	if len(users) != 1 || users[0].Username != "bob" {
		t.Fatalf("users = %+v, want only bob", users)
	}
}

// S-3: PATCH finds the user by name without case, like POST.
func TestPatchInboundUserCaseInsensitive(t *testing.T) {
	name := "route-patch-case"
	startRouteVless(t, name, []inbound.VlessUser{{Username: "alice", UUID: utils.NewUUIDV4().String()}})

	newUUID := utils.NewUUIDV4().String()
	code, body := serveInbounds(t, http.MethodPatch, "/"+name+"/users/ALICE", `{"uuid":"`+newUUID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	users, _ := listener.GetInboundUsers(name)
	if len(users) != 1 || users[0].Username != "alice" || users[0].UUID != newUUID {
		t.Fatalf("users = %+v", users)
	}
}
