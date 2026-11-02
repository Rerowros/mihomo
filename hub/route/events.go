package route

import (
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// eventsDroppedInterval is how often a stream reports the events dropped for
// it because it read too slowly.
var eventsDroppedInterval = 5 * time.Second

// eventsBuffer is the number of events a stream may lag behind before events
// are dropped for it.
var eventsBuffer = eventbus.DefaultBuffer

// eventsHeartbeat is how often a stream sends a keep-alive (an SSE comment, an
// empty line of NDJSON, a websocket ping), so that a reverse proxy does not
// close a quiet stream (nginx proxy_read_timeout is 60 s by default).
var eventsHeartbeat = 25 * time.Second

// eventsMaxStreams caps the open streams; each holds a subscription and a
// goroutine, so a client that leaks them gets 429 instead of growing the core.
var eventsMaxStreams int64 = 32

var eventsStreams atomic.Int64

// getEvents serves GET /events: the core events as they happen, filtered by
// ?types=user.session,user.limit (all types without it). Like /logs and /traffic it
// is a websocket when the request asks for an upgrade (one JSON event per
// text message), otherwise a chunked response of newline-delimited JSON, or
// Server-Sent Events with Accept: text/event-stream.
func getEvents(w http.ResponseWriter, r *http.Request) {
	mask, err := eventbus.ParseTypes(r.URL.Query().Get("types"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	if eventsStreams.Add(1) > eventsMaxStreams {
		eventsStreams.Add(-1)
		render.Status(r, http.StatusTooManyRequests)
		render.JSON(w, r, newError("too many event streams"))
		return
	}
	defer eventsStreams.Add(-1)

	sub := eventbus.Subscribe(mask, eventsBuffer)
	defer sub.Close()

	var write func(e eventbus.Event) error
	var heartbeat func() error
	// The request context ends when the client goes away or when the
	// controller server is closed (a restart with a new secret, see
	// newServer); a hijacked websocket also ends when its reader fails.
	ctxDone := r.Context().Done()
	var closed chan struct{}
	if r.Header.Get("Upgrade") == "websocket" {
		conn, _, err := wsUpgrade(r, w)
		if err != nil {
			return
		}
		defer conn.Close()
		closed = make(chan struct{})
		go func() { // the client sends nothing we use; a read error is the end
			_, _ = io.Copy(io.Discard, conn)
			close(closed)
		}()
		write = func(e eventbus.Event) error {
			buf, err := json.Marshal(e)
			if err != nil {
				return err
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			return wsWriteServerText(conn, buf)
		}
		heartbeat = func() error {
			const opPing = 0x9
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			return wsWriteServerMessage(conn, opPing, nil)
		}
	} else {
		flusher, ok := w.(http.Flusher)
		if !ok {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("streaming unsupported"))
			return
		}
		sse := strings.Contains(r.Header.Get("Accept"), "text/event-stream")
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/x-ndjson")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		// A client that stopped reading must not hold a stream slot forever.
		rc := http.NewResponseController(w)
		write = func(e eventbus.Event) error {
			buf, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if sse {
				buf = append(append([]byte("event: "+e.Type+"\ndata: "), buf...), '\n', '\n')
			} else {
				buf = append(buf, '\n')
			}
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err = w.Write(buf); err != nil {
				return err
			}
			flusher.Flush()
			return nil
		}
		keepAlive := []byte("\n") // NDJSON readers skip empty lines
		if sse {
			keepAlive = []byte(":\n\n") // an SSE comment
		}
		heartbeat = func() error {
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := w.Write(keepAlive); err != nil {
				return err
			}
			flusher.Flush()
			return nil
		}
	}

	tick := time.NewTicker(eventsDroppedInterval)
	defer tick.Stop()
	beat := time.NewTicker(eventsHeartbeat)
	defer beat.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case <-closed:
			return
		case <-beat.C:
			if heartbeat() != nil {
				return
			}
		case e, ok := <-sub.C():
			if !ok {
				return
			}
			if write(e) != nil {
				return
			}
		case <-tick.C:
			if n := sub.TakeDropped(); n > 0 {
				e := eventbus.Event{Type: eventbus.TypeDropped, Time: time.Now(), Data: eventbus.Dropped{Count: n}}
				if write(e) != nil {
					return
				}
			}
		}
	}
}
