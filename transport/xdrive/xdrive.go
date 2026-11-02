package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionsDir = "sessions"
	streamsDir  = "streams"
	uplinkDir   = "c2s"
	downlinkDir = "s2c"
)

func newSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("xdrive: generate session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func announceName(session string, at time.Time) string {
	return fmt.Sprintf("%s/%d-%s", sessionsDir, at.UnixNano(), session)
}

func parseAnnounce(entry string) (string, time.Time, bool) {
	dash := strings.IndexByte(entry, '-')
	if dash <= 0 || dash == len(entry)-1 {
		return "", time.Time{}, false
	}
	nanos, err := strconv.ParseInt(entry[:dash], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return entry[dash+1:], time.Unix(0, nanos), true
}

func sessionPrefix(session string) string {
	return streamsDir + "/" + session
}

func uplinkPrefix(session string) string {
	return sessionPrefix(session) + "/" + uplinkDir
}

func downlinkPrefix(session string) string {
	return sessionPrefix(session) + "/" + downlinkDir
}

// Client is the dialing side of the transport: every Dial announces a new
// session in the shared folder and returns a net.Conn over its c2s/s2c object
// streams. It is safe for concurrent Dial calls; they share the storage
// (access token, id cache, HTTP connections).
type Client struct {
	storage Storage
	params  params
}

func NewClient(config *Config) (*Client, error) {
	p, err := config.normalized()
	if err != nil {
		return nil, err
	}
	storage, err := sharedStorage(config)
	if err != nil {
		return nil, err
	}
	return &Client{storage: storage, params: p}, nil
}

func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	session, err := newSessionID()
	if err != nil {
		return nil, err
	}
	if err := c.storage.Put(ctx, announceName(session, time.Now()), nil); err != nil {
		return nil, fmt.Errorf("xdrive: announce session %s: %w", session, err)
	}
	return newConn(context.Background(), c.storage,
		uplinkPrefix(session), downlinkPrefix(session), c.params, nil), nil
}

func (c *Client) Close() error {
	// The storage is shared between sessions (and possibly processes on the
	// same machine); it is not closed here.
	return nil
}

// Listener is the accepting side: it polls the sessions directory and hands a
// net.Conn for every new session to the connection handler. It opens no TCP
// socket.
type Listener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	storage Storage
	params
	addConn func(net.Conn)

	mu        sync.Mutex
	active    map[string]bool
	handled   map[string]time.Time
	idleSince map[string]time.Time
}

// Listen starts the session poller. addConn is called from its own goroutine
// for every accepted session.
func Listen(config *Config, addConn func(net.Conn)) (*Listener, error) {
	p, err := config.normalized()
	if err != nil {
		return nil, err
	}
	storage, err := sharedStorage(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	listener := &Listener{
		ctx:       ctx,
		cancel:    cancel,
		storage:   storage,
		params:    p,
		addConn:   addConn,
		active:    make(map[string]bool),
		handled:   make(map[string]time.Time),
		idleSince: make(map[string]time.Time),
	}
	go listener.acceptLoop()
	go listener.collectLoop()
	return listener, nil
}

func (l *Listener) acceptLoop() {
	delay := l.minPollInterval
	active := time.Now()
	for {
		accepted, err := l.acceptPending()
		if err != nil && l.ctx.Err() == nil {
			// A listing error is not fatal: the next poll retries it.
			delay = l.minPollInterval
		}

		switch {
		case accepted:
			active = time.Now()
			delay = l.minPollInterval
		case time.Since(active) < l.eagerWindow:
			delay = l.minPollInterval
		default:
			delay *= 2
			if delay > l.maxPollInterval {
				delay = l.maxPollInterval
			}
		}

		select {
		case <-l.ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (l *Listener) acceptPending() (bool, error) {
	sessions, err := l.storage.List(l.ctx, sessionsDir)
	if err != nil {
		return false, err
	}

	accepted := false
	for _, listed := range sessions {
		entry := listed.Name
		full := sessionsDir + "/" + entry

		session, at, ok := parseAnnounce(entry)
		if !ok {
			go l.drop(full)
			continue
		}
		if time.Since(at) > l.sessionTTL {
			go l.drop(full)
			go l.drop(sessionPrefix(session))
			continue
		}
		if !l.claim(session) {
			continue
		}
		go l.drop(full)
		accepted = true
		conn := l.newSessionConn(session)
		go l.addConn(conn)
	}
	return accepted, nil
}

func (l *Listener) drop(name string) {
	_ = l.storage.Delete(l.ctx, name)
}

func (l *Listener) claim(session string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[session] || !l.handled[session].IsZero() {
		return false
	}
	l.active[session] = true
	l.handled[session] = time.Now()
	return true
}

func (l *Listener) newSessionConn(session string) *Conn {
	return newConn(l.ctx, l.storage,
		downlinkPrefix(session), uplinkPrefix(session), l.params, func() {
			l.mu.Lock()
			delete(l.active, session)
			l.mu.Unlock()
		})
}

func (l *Listener) collectLoop() {
	interval := l.sessionTTL / 2
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-time.After(interval):
		}
		_ = l.collect()
	}
}

func (l *Listener) collect() error {
	sessions, err := l.storage.List(l.ctx, streamsDir)
	if err != nil {
		return err
	}

	now := time.Now()
	var expired []string

	l.mu.Lock()
	present := make(map[string]bool, len(sessions))
	for _, listed := range sessions {
		session := listed.Name
		present[session] = true
		if l.active[session] {
			delete(l.idleSince, session)
			continue
		}
		since, seen := l.idleSince[session]
		if !seen {
			l.idleSince[session] = now
			continue
		}
		if now.Sub(since) >= l.sessionTTL {
			expired = append(expired, session)
			delete(l.idleSince, session)
		}
	}
	for session := range l.idleSince {
		if !present[session] {
			delete(l.idleSince, session)
		}
	}
	for session, at := range l.handled {
		if !l.active[session] && now.Sub(at) >= l.sessionTTL {
			delete(l.handled, session)
		}
	}
	l.mu.Unlock()

	for _, session := range expired {
		if err := l.storage.Delete(l.ctx, sessionPrefix(session)); err != nil {
			return err
		}
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	return placeholderAddr
}

func (l *Listener) Close() error {
	l.cancel()
	return nil
}
