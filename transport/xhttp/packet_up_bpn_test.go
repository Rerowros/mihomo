package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BadVPN patch P5: packet-up sends up to PacketUpMaxInFlight upload requests
// of a session in parallel, like Xray.

// bpnUploadServer is a packet-up upload endpoint that delays its responses.
// It puts the payloads back in order by seq, as Xray and mihomo servers do.
type bpnUploadServer struct {
	t      *testing.T
	cfg    *Config
	addr   string
	delay  func(seq uint64) time.Duration // before the payload is accepted
	status func(seq uint64) int           // response status, 200 if nil

	queue    *UploadQueue
	received chan []byte // reassembled stream, closed by close()

	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	requests    atomic.Int32
}

func startBPNUploadServer(t *testing.T, cfg *Config, delay func(seq uint64) time.Duration) *bpnUploadServer {
	t.Helper()
	s := &bpnUploadServer{
		t:        t,
		cfg:      cfg,
		delay:    delay,
		queue:    NewUploadQueue(30), // default sc-max-buffered-posts
		received: make(chan []byte, 1),
	}
	go func() {
		var got bytes.Buffer
		_, _ = io.Copy(&got, s.queue)
		s.received <- got.Bytes()
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: s, Protocols: protocols}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = s.queue.Close()
	})
	s.addr = ln.Addr().String()
	return s
}

func (s *bpnUploadServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		m := s.maxInFlight.Load()
		if n <= m || s.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	s.requests.Add(1)

	_, seqStr := s.cfg.ExtractMetaFromRequest(r, s.cfg.NormalizedPath())
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		http.Error(w, "no seq", http.StatusBadRequest)
		return
	}
	var payload []byte
	if s.cfg.GetNormalizedUplinkDataPlacement() == PlacementHeader {
		var encoded strings.Builder
		for i := 0; ; i++ {
			chunk := r.Header.Get(fmt.Sprintf("%s-%d", s.cfg.UplinkDataKey, i))
			if chunk == "" {
				break
			}
			encoded.WriteString(chunk)
		}
		payload, err = base64.RawURLEncoding.DecodeString(encoded.String())
	} else {
		payload, err = io.ReadAll(r.Body)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if s.delay != nil {
		select {
		case <-time.After(s.delay(seq)):
		case <-r.Context().Done():
			return
		}
	}
	if s.status != nil {
		if status := s.status(seq); status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
	}
	if err := s.queue.Push(Packet{Seq: seq, Payload: payload}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// stream closes the upload queue once all requests are done and returns the
// reassembled stream.
func (s *bpnUploadServer) stream(t *testing.T) []byte {
	t.Helper()
	require.Eventually(t, func() bool { return s.inFlight.Load() == 0 }, 5*time.Second, 5*time.Millisecond)
	_ = s.queue.Close()
	select {
	case got := <-s.received:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("upload queue reader did not finish")
		return nil
	}
}

// bpnRecordingTransport records when requests are handed to the transport
// and how many are in flight on the client side.
type bpnRecordingTransport struct {
	inner       http.RoundTripper
	mu          sync.Mutex
	starts      []time.Time
	seqs        []uint64
	inFlight    int
	maxInFlight int
	cfg         *Config
}

func (r *bpnRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	_, seqStr := r.cfg.ExtractMetaFromRequest(req, r.cfg.NormalizedPath())
	seq, _ := strconv.ParseUint(seqStr, 10, 64)
	r.mu.Lock()
	r.starts = append(r.starts, time.Now())
	r.seqs = append(r.seqs, seq)
	r.inFlight++
	if r.inFlight > r.maxInFlight {
		r.maxInFlight = r.inFlight
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.inFlight--
		r.mu.Unlock()
	}()
	resp, err := r.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// the writer reads the whole body before it frees the slot
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, err
}

func (r *bpnRecordingTransport) CloseIdleConnections() {
	if tr, ok := r.inner.(interface{ CloseIdleConnections() }); ok {
		tr.CloseIdleConnections()
	}
}

func (r *bpnRecordingTransport) snapshot() (starts []time.Time, seqs []uint64, maxInFlight int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.starts...), append([]uint64(nil), r.seqs...), r.maxInFlight
}

type bpnPacketUpCase struct {
	name string
	cfg  func() *Config
	alpn []string
}

func bpnPacketUpCases() []bpnPacketUpCase {
	postCfg := func() *Config {
		return &Config{Host: "example.com", Path: "/xhttp", Mode: "packet-up"}
	}
	getCfg := func() *Config {
		// uplink in X-Payload-N headers, like a CDN that does not pass POST
		return &Config{
			Host:                "example.com",
			Path:                "/xhttp",
			Mode:                "packet-up",
			UplinkHTTPMethod:    http.MethodGet,
			UplinkDataPlacement: PlacementHeader,
			UplinkDataKey:       "X-Payload",
			UplinkChunkSize:     "8192-12288",
		}
	}
	return []bpnPacketUpCase{
		{name: "post-h2", cfg: postCfg},
		{name: "get-header-h2", cfg: getCfg},
		{name: "post-h1", cfg: postCfg, alpn: []string{"http/1.1"}},
		{name: "get-header-h1", cfg: getCfg, alpn: []string{"http/1.1"}},
	}
}

func newBPNTestWriter(t *testing.T, cfg *Config, addr string, alpn []string, maxEachPostBytes int,
	interval Range, maxInFlight int) (*PacketUpWriter, *bpnRecordingTransport) {
	t.Helper()
	inner := NewTransport(
		func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error) { return conn, nil },
		nil, alpn, 0)
	rec := &bpnRecordingTransport{inner: inner, cfg: cfg}
	w := newPacketUpWriter(context.Background(), cfg, maxEachPostBytes, interval, "bpn-session", rec, maxInFlight)
	return w, rec
}

// bpnWriterGoroutines counts goroutines running PacketUpWriter code.
func bpnWriterGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "xhttp.(*PacketUpWriter)") && !strings.Contains(g, "bpnWriterGoroutines") {
			count++
		}
	}
	return count
}

func requireNoBPNWriterGoroutines(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return bpnWriterGoroutines() == 0 }, 3*time.Second, 10*time.Millisecond,
		"PacketUpWriter goroutines left after Close")
}

func bpnRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// (a) Up to N requests are in flight at once, never more; N = 1 is the old
// strictly sequential behaviour.
func TestBPNPacketUpConcurrency(t *testing.T) {
	for _, tc := range bpnPacketUpCases() {
		for _, n := range []int{1, 4} {
			t.Run(fmt.Sprintf("%s/n=%d", tc.name, n), func(t *testing.T) {
				cfg := tc.cfg()
				server := startBPNUploadServer(t, cfg, func(uint64) time.Duration { return 150 * time.Millisecond })
				const chunk = 16 * 1024
				w, rec := newBPNTestWriter(t, cfg, server.addr, tc.alpn, chunk, Range{Min: 5, Max: 5}, n)

				data := bpnRandomBytes(t, 12*chunk)
				start := time.Now()
				_, err := w.Write(data)
				require.NoError(t, err)
				require.NoError(t, w.Close())
				elapsed := time.Since(start)

				got := server.stream(t)
				assert.Equal(t, sha256.Sum256(data), sha256.Sum256(got))
				_, seqs, maxInFlight := rec.snapshot()
				assert.Len(t, seqs, 12)
				assert.Equal(t, n, maxInFlight, "client requests in flight")
				assert.LessOrEqual(t, int(server.maxInFlight.Load()), n, "server requests in flight")
				t.Logf("n=%d: 12 requests of %d KB with 150 ms responses in %v", n, chunk/1024, elapsed)
				if n == 1 {
					assert.GreaterOrEqual(t, elapsed, 12*150*time.Millisecond)
				} else {
					assert.Less(t, elapsed, 12*150*time.Millisecond/2)
				}
				requireNoBPNWriterGoroutines(t)
			})
		}
	}
}

// (b) seq follows the send order and the server reassembles the stream even
// when the requests complete out of order.
func TestBPNPacketUpSeqOrderAndReassembly(t *testing.T) {
	for _, tc := range bpnPacketUpCases() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg()
			// random delays make the requests complete (and reach the reorder
			// queue) out of order
			server := startBPNUploadServer(t, cfg, func(uint64) time.Duration {
				return time.Duration(mathrand.Intn(60)) * time.Millisecond
			})
			w, rec := newBPNTestWriter(t, cfg, server.addr, tc.alpn, 32*1024, Range{Min: 0, Max: 2}, PacketUpMaxInFlight)

			data := bpnRandomBytes(t, 2*1024*1024+123)
			for rest := data; len(rest) > 0; {
				n := 1 + mathrand.Intn(48*1024)
				if n > len(rest) {
					n = len(rest)
				}
				written, err := w.Write(rest[:n])
				require.NoError(t, err)
				require.Equal(t, n, written)
				rest = rest[n:]
			}
			require.NoError(t, w.Close())

			got := server.stream(t)
			require.Equal(t, len(data), len(got))
			assert.Equal(t, sha256.Sum256(data), sha256.Sum256(got))

			// seq is assigned in send order: every seq once, and a request
			// reaches the transport at most N places away from its seq
			_, seqs, maxInFlight := rec.snapshot()
			seen := make(map[uint64]bool, len(seqs))
			for i, seq := range seqs {
				require.False(t, seen[seq], "seq %d sent twice", seq)
				seen[seq] = true
				require.InDelta(t, i, seq, PacketUpMaxInFlight, "seq %d sent as request %d", seq, i)
			}
			for seq := range seqs {
				require.True(t, seen[uint64(seq)], "seq %d missing", seq)
			}
			t.Logf("%d requests, up to %d in flight", len(seqs), maxInFlight)
			requireNoBPNWriterGoroutines(t)
		})
	}
}

// (c) A failed request tears the session down: the other requests in flight
// are aborted and Write returns the error.
func TestBPNPacketUpErrorClosesSession(t *testing.T) {
	for _, tc := range bpnPacketUpCases() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg()
			server := startBPNUploadServer(t, cfg, func(seq uint64) time.Duration {
				if seq == 3 {
					return 20 * time.Millisecond
				}
				return 5 * time.Second
			})
			server.status = func(seq uint64) int {
				if seq == 3 {
					return http.StatusServiceUnavailable
				}
				return http.StatusOK
			}
			w, rec := newBPNTestWriter(t, cfg, server.addr, tc.alpn, 8*1024, Range{Min: 1, Max: 1}, PacketUpMaxInFlight)

			start := time.Now()
			var err error
			for i := 0; i < 1000 && err == nil; i++ {
				_, err = w.Write(bpnRandomBytes(t, 8*1024))
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "bad status")
			assert.Less(t, time.Since(start), 3*time.Second, "the error must not wait for the slow requests")

			// the requests still waiting for the slow responses are aborted
			require.Eventually(t, func() bool {
				rec.mu.Lock()
				defer rec.mu.Unlock()
				return rec.inFlight == 0
			}, 2*time.Second, 5*time.Millisecond)

			_, err = w.Write([]byte("more"))
			assert.Error(t, err)
			require.NoError(t, w.Close())
			requireNoBPNWriterGoroutines(t)
		})
	}
}

// (d) Requests start at least sc-min-posts-interval-ms apart, even when their
// responses are slow and there is always data to send.
func TestBPNPacketUpMinPostsInterval(t *testing.T) {
	const interval = 40
	cfg := &Config{Host: "example.com", Path: "/xhttp", Mode: "packet-up"}
	server := startBPNUploadServer(t, cfg, func(uint64) time.Duration { return 300 * time.Millisecond })
	w, rec := newBPNTestWriter(t, cfg, server.addr, nil, 4*1024, Range{Min: interval, Max: interval}, PacketUpMaxInFlight)

	data := bpnRandomBytes(t, 16*4*1024)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	assert.Equal(t, sha256.Sum256(data), sha256.Sum256(server.stream(t)))

	starts, _, maxInFlight := rec.snapshot()
	require.Len(t, starts, 16)
	minGap := time.Hour
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < minGap {
			minGap = gap
		}
	}
	t.Logf("min gap between request starts %v, up to %d in flight", minGap, maxInFlight)
	assert.GreaterOrEqual(t, minGap, interval*time.Millisecond-3*time.Millisecond)
	// 300 ms responses / 40 ms interval: 7-8 requests overlap
	assert.GreaterOrEqual(t, maxInFlight, 6)
	requireNoBPNWriterGoroutines(t)
}

// (e) Close does not leak goroutines, also when requests are stuck and Write
// is blocked on a full pipeline; later writes fail.
func TestBPNPacketUpCloseWhileBlocked(t *testing.T) {
	cfg := &Config{Host: "example.com", Path: "/xhttp", Mode: "packet-up"}
	server := startBPNUploadServer(t, cfg, func(uint64) time.Duration { return time.Minute })
	w, rec := newBPNTestWriter(t, cfg, server.addr, nil, 1024, Range{Min: 1, Max: 1}, 2)

	writeDone := make(chan error, 1)
	go func() {
		_, err := w.Write(bpnRandomBytes(t, 64*1024)) // blocks: 2 requests stuck, buffer full
		writeDone <- err
	}()
	require.Eventually(t, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return rec.inFlight == 2
	}, 2*time.Second, 5*time.Millisecond)
	select {
	case err := <-writeDone:
		t.Fatalf("Write returned while the pipeline is full: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_, _, maxInFlight := rec.snapshot()
	assert.Equal(t, 2, maxInFlight)

	start := time.Now()
	require.NoError(t, w.Close())
	assert.Less(t, time.Since(start), 3*time.Second)
	select {
	case err := <-writeDone:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Write still blocked after Close")
	}
	_, err := w.Write([]byte("after close"))
	assert.Error(t, err)
	requireNoBPNWriterGoroutines(t)
}

// Close sends the buffered tail and waits for the requests in flight.
func TestBPNPacketUpCloseDeliversTail(t *testing.T) {
	cfg := &Config{Host: "example.com", Path: "/xhttp", Mode: "packet-up"}
	server := startBPNUploadServer(t, cfg, func(uint64) time.Duration { return 100 * time.Millisecond })
	w, _ := newBPNTestWriter(t, cfg, server.addr, nil, 8*1024, Range{Min: 30, Max: 30}, PacketUpMaxInFlight)

	data := bpnRandomBytes(t, 3*8*1024+100)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	assert.Equal(t, sha256.Sum256(data), sha256.Sum256(server.stream(t)))
	requireNoBPNWriterGoroutines(t)
}

// Upload throughput with a 150 ms response delay (a CDN round trip):
// sequential (N = 1, upstream) vs parallel (N = PacketUpMaxInFlight).
func TestBPNPacketUpThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for _, tc := range bpnPacketUpCases()[:2] { // h2: POST body and GET headers
		t.Run(tc.name, func(t *testing.T) {
			var rate [2]float64
			for i, n := range []int{1, PacketUpMaxInFlight} {
				cfg := tc.cfg()
				cfg.ScMaxEachPostBytes = "65536"
				server := startBPNUploadServer(t, cfg, func(uint64) time.Duration { return 150 * time.Millisecond })
				w, _ := newBPNTestWriter(t, cfg, server.addr, tc.alpn, 64*1024, Range{Min: 30, Max: 30}, n)
				data := bpnRandomBytes(t, 1024*1024)
				start := time.Now()
				_, err := w.Write(data)
				require.NoError(t, err)
				require.NoError(t, w.Close())
				got := server.stream(t)
				elapsed := time.Since(start)
				require.Equal(t, sha256.Sum256(data), sha256.Sum256(got))
				rate[i] = float64(len(data)) * 8 / elapsed.Seconds() / 1e6
				t.Logf("THROUGHPUT %s n=%d: 1 MiB in %v = %.1f Mbit/s", tc.name, n, elapsed.Round(time.Millisecond), rate[i])
			}
			assert.Greater(t, rate[1], 3*rate[0])
			requireNoBPNWriterGoroutines(t)
		})
	}
}

// The whole packet-up client (download GET + parallel uploads) against the
// mihomo server handler, which echoes the stream back.
func TestBPNPacketUpClientEchoWithServerHandler(t *testing.T) {
	cfg := Config{Host: "example.com", Path: "/xhttp", Mode: "packet-up", ScMaxEachPostBytes: "65536"}
	handler, err := NewServerHandler(ServerOption{
		Config: cfg,
		ConnHandler: func(conn net.Conn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
	})
	require.NoError(t, err)
	var maxInFlight, inFlight atomic.Int32
	delayed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Count(strings.Trim(r.URL.Path, "/"), "/") == 2 { // /xhttp/{session}/{seq}
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for m := maxInFlight.Load(); n > m && !maxInFlight.CompareAndSwap(m, n); m = maxInFlight.Load() {
			}
			time.Sleep(time.Duration(20+mathrand.Intn(60)) * time.Millisecond)
		}
		handler.ServeHTTP(w, r)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{Handler: delayed, Protocols: protocols}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })

	addr := ln.Addr().String()
	client, err := NewClient(&cfg, func() http.RoundTripper {
		return NewTransport(
			func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", addr)
			},
			func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error) { return conn, nil },
			nil, nil, 0)
	}, nil, false)
	require.NoError(t, err)
	defer client.Close()

	conn, err := client.Dial(context.Background())
	require.NoError(t, err)
	data := bpnRandomBytes(t, 4*1024*1024)
	readDone := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(data))
		_, _ = io.ReadFull(conn, got)
		readDone <- got
	}()
	_, err = conn.Write(data)
	require.NoError(t, err)
	select {
	case got := <-readDone:
		assert.Equal(t, sha256.Sum256(data), sha256.Sum256(got))
	case <-time.After(30 * time.Second):
		t.Fatal("echo timed out")
	}
	require.NoError(t, conn.Close())
	t.Logf("server saw up to %d upload requests in flight", maxInFlight.Load())
	assert.Greater(t, int(maxInFlight.Load()), 1)
	assert.LessOrEqual(t, int(maxInFlight.Load()), PacketUpMaxInFlight)
	requireNoBPNWriterGoroutines(t)
}
