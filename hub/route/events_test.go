package route

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type streamedEvent struct {
	Type string          `json:"type"`
	Time time.Time       `json:"time"`
	Data json.RawMessage `json:"data"`
}

func eventsServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(router(false, testSecret, "", Cors{}))
	t.Cleanup(srv.Close)
	return srv
}

// openEvents opens a chunked stream; the subscription exists once it returns.
func openEvents(t *testing.T, srv *httptest.Server, query, accept string) (*bufio.Reader, func()) {
	t.Helper()
	req, err := stdhttp.NewRequest(stdhttp.MethodGet, srv.URL+"/events"+query, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := stdhttp.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, stdhttp.StatusOK, resp.StatusCode)
	return bufio.NewReader(resp.Body), func() { _ = resp.Body.Close() }
}

func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		require.NoError(t, res.err)
		return strings.TrimRight(res.line, "\n")
	case <-time.After(3 * time.Second):
		t.Fatal("no event on the stream")
		return ""
	}
}

func readEvent(t *testing.T, r *bufio.Reader) streamedEvent {
	t.Helper()
	var e streamedEvent
	line := readLine(t, r)
	require.NoError(t, json.Unmarshal([]byte(line), &e), line)
	return e
}

func TestEventsRequests(t *testing.T) {
	h := router(false, testSecret, "", Cors{})
	assert.Equal(t, stdhttp.StatusUnauthorized, get(h, "/events", "").Code, "behind the controller secret")
	assert.Equal(t, stdhttp.StatusUnauthorized, get(h, "/events", "wrong").Code)
	rec := get(h, "/events?types=user.session,bogus", testSecret)
	assert.Equal(t, stdhttp.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "bogus")
}

// The hooks in the core reach a chunked stream: a user revoked through the
// runtime user table and a connection refused by a limit.
func TestEventsChunkedRealHooks(t *testing.T) {
	const uuidA, uuidB = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	name := fmt.Sprintf("ev-vless-%d", time.Now().UnixNano())
	startRouteVless(t, name, []inbound.VlessUser{{Username: "alice", UUID: uuidA}, {Username: "bob", UUID: uuidB}})

	srv := eventsServer(t)
	r, closeStream := openEvents(t, srv, "?types=user.revoked,user.limit", "")
	defer closeStream()

	change, err := listener.SetInboundUsers(name, []C.InboundUser{{Username: "bob", UUID: uuidB}})
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, change.Revoked)
	e := readEvent(t, r)
	require.Equal(t, eventbus.TypeUserRevoked, e.Type)
	assert.JSONEq(t, `{"inbound":"`+name+`","users":["alice"],"closed":0}`, string(e.Data))

	// a change that revokes nobody is not reported
	_, err = listener.UpdateInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		return append(users, C.InboundUser{Username: "carol", UUID: uuidA}), nil
	})
	require.NoError(t, err)

	key := statistic.UserKey{Inbound: name, User: "bob"}
	statistic.DefaultLimitManager.Set(statistic.UserLimit{Inbound: name, User: "bob", MaxConns: 1})
	t.Cleanup(func() { statistic.DefaultLimitManager.Delete(name, "bob") })
	slot, err := statistic.DefaultLimitManager.Admit(key)
	require.NoError(t, err)
	defer slot.Release()
	_, err = statistic.DefaultLimitManager.Admit(key)
	require.ErrorIs(t, err, statistic.ErrUserMaxConns)
	e = readEvent(t, r)
	require.Equal(t, eventbus.TypeUserLimit, e.Type, "the second update revoked nobody, so the next event is the limit")
	assert.JSONEq(t, `{"inbound":"`+name+`","user":"bob","reason":"max-conns","action":"rejected"}`, string(e.Data))
}

// SSE framing, with a configuration reload that failed.
func TestEventsSSE(t *testing.T) {
	srv := eventsServer(t)
	r, closeStream := openEvents(t, srv, "?types=config.reload", "text/event-stream")
	defer closeStream()

	// a configuration that does not parse, through the controller
	req, err := stdhttp.NewRequest(stdhttp.MethodPut, srv.URL+"/configs", strings.NewReader(`{"payload":"proxies: ["}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	resp, err := stdhttp.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, stdhttp.StatusBadRequest, resp.StatusCode)

	assert.Equal(t, "event: config.reload", readLine(t, r))
	data := readLine(t, r)
	require.True(t, strings.HasPrefix(data, "data: "), data)
	var e streamedEvent
	require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(data, "data: ")), &e))
	var d eventbus.ConfigReload
	require.NoError(t, json.Unmarshal(e.Data, &d))
	assert.Equal(t, eventbus.StatusError, d.Status)
	assert.NotEmpty(t, d.Error)
	assert.Equal(t, "", readLine(t, r))
}

func TestEventsDropped(t *testing.T) {
	oldBuf, oldInterval := eventsBuffer, eventsDroppedInterval
	eventsBuffer, eventsDroppedInterval = 1, 50*time.Millisecond
	t.Cleanup(func() { eventsBuffer, eventsDroppedInterval = oldBuf, oldInterval })

	srv := eventsServer(t)
	r, closeStream := openEvents(t, srv, "?types=config.reload", "")
	defer closeStream()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			eventbus.PublishConfigReload(nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("publishing blocked on a slow stream")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		e := readEvent(t, r)
		if e.Type == eventbus.TypeDropped {
			var d eventbus.Dropped
			require.NoError(t, json.Unmarshal(e.Data, &d))
			assert.Greater(t, d.Count, uint64(0))
			return
		}
		require.Equal(t, eventbus.TypeConfigReload, e.Type)
	}
	t.Fatal("no dropped event")
}

// wsReadText reads one unmasked server text frame.
func wsReadText(r io.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0]&0x0f != 0x1 {
		return "", errors.New("not a text frame")
	}
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return string(buf), err
}

func TestEventsWebSocket(t *testing.T) {
	srv := eventsServer(t)
	before := eventbus.Default.Subscribers()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// a browser passes the secret as ?token=
	_, err = fmt.Fprintf(conn, "GET /events?types=config.reload&token=%s HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", testSecret)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := stdhttp.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, stdhttp.StatusSwitchingProtocols, resp.StatusCode)
	assert.Equal(t, before+1, eventbus.Default.Subscribers())

	eventbus.PublishConfigReload(errors.New("bad yaml"))
	msg, err := wsReadText(br)
	require.NoError(t, err)
	var e streamedEvent
	require.NoError(t, json.Unmarshal([]byte(msg), &e))
	assert.Equal(t, eventbus.TypeConfigReload, e.Type)
	assert.JSONEq(t, `{"status":"error","error":"bad yaml"}`, string(e.Data))

	// the client goes away: the subscription is released
	_ = conn.Close()
	require.Eventually(t, func() bool { return eventbus.Default.Subscribers() == before }, 3*time.Second, 10*time.Millisecond)
}
