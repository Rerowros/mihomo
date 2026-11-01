package fragment

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/fragment/dpifilter"

	"github.com/stretchr/testify/require"
)

// writeLog records every Write that reaches the layer below it.
type writeLog struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (w *writeLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes = append(w.writes, append([]byte(nil), p...))
	w.mu.Unlock()
	return w.Conn.Write(p)
}

func (w *writeLog) all() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.writes...)
}

func mustParse(t *testing.T, o Options) *Config {
	t.Helper()
	c, err := o.Parse()
	require.NoError(t, err)
	require.NotNil(t, c)
	return c
}

// startTLSEcho runs a crypto/tls server that echoes everything back.
func startTLSEcho(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// handshake dials addr, puts the fragment layer (cfg may be nil) between TLS
// and TCP, and returns what TLS wrote (above) and what went to TCP (below).
func handshake(t *testing.T, addr string, cfg *Config) (*tls.Conn, *writeLog, *writeLog) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	below := &writeLog{Conn: raw}
	above := &writeLog{Conn: NewConn(below, cfg)}
	conn := tls.Client(above, &tls.Config{ServerName: "blocked.example.com", InsecureSkipVerify: true})
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	return conn, above, below
}

// records splits a byte stream into TLS records.
func records(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		require.GreaterOrEqual(t, len(b), 5, "truncated record header")
		n := int(binary.BigEndian.Uint16(b[3:]))
		require.GreaterOrEqual(t, len(b), 5+n, "truncated record")
		out = append(out, b[:5+n])
		b = b[5+n:]
	}
	return out
}

func echoSHA256(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, size)
	_, err := io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(payload), sha256.Sum256(got))
}

func TestBPNFragmentParse(t *testing.T) {
	c, err := Options{}.Parse()
	require.NoError(t, err)
	require.Nil(t, c, "empty block must mean off")

	c = mustParse(t, Options{Packets: "tlshello", Length: "10-20", Delay: "0"})
	require.True(t, c.tlsHello)
	require.Equal(t, rng{10, 20}, c.length)
	require.Equal(t, rng{0, 0}, c.delay)

	c = mustParse(t, Options{Packets: "1-3", Length: "5", Delay: "2-4", MaxSplit: "8"})
	require.False(t, c.tlsHello)
	require.Equal(t, 1, c.packetsLo)
	require.Equal(t, 3, c.packetsHi)
	require.Equal(t, rng{5, 5}, c.length)
	require.Equal(t, rng{2, 4}, c.delay)
	require.Equal(t, rng{8, 8}, c.maxSplit)

	c = mustParse(t, Options{Delay: "5"}) // packets and length default to tlshello / 10-20
	require.True(t, c.tlsHello)
	require.Equal(t, rng{10, 20}, c.length)

	for _, bad := range []Options{
		{Packets: "0-1"},
		{Packets: "abc"},
		{Length: "0-5"},
		{Length: "20-10"},
		{Delay: "-1"},
		{MaxSplit: "x"},
	} {
		_, err := bad.Parse()
		require.Error(t, err, "%+v", bad)
	}
	require.Nil(t, NewConn(nil, nil))
}

// tlshello, delay 0: one write, many TLS records of 10..20 bytes of payload;
// the server still completes the handshake; application data is not touched.
func TestBPNFragmentTLSHelloMerged(t *testing.T) {
	addr := startTLSEcho(t)
	conn, above, below := handshake(t, addr, mustParse(t, Options{Packets: "tlshello", Length: "10-20", Delay: "0"}))
	require.NoError(t, conn.Handshake())

	original := above.all()[0]
	wire := below.all()
	require.Greater(t, len(original), 200)
	require.Equal(t, byte(22), original[0])
	require.Len(t, records(t, original), 1, "TLS wrote the ClientHello as one record")

	hello := wire[0]
	parts := records(t, hello)
	require.Greater(t, len(parts), (len(original)-5)/20, "ClientHello must be cut into many records")
	var joined []byte
	for i, part := range parts {
		require.Equal(t, original[:3], part[:3], "record %d keeps type and version", i)
		l := len(part) - 5
		if i < len(parts)-1 {
			require.GreaterOrEqual(t, l, 10, "record %d", i)
		}
		require.LessOrEqual(t, l, 20, "record %d", i)
		joined = append(joined, part[5:]...)
	}
	require.Equal(t, original[5:], joined, "payloads join back into the same ClientHello")
	t.Logf("ClientHello %d bytes -> %d records, %d bytes on the wire in 1 write", len(original), len(parts), len(hello))

	echoSHA256(t, conn, 256*1024)
	aboveWrites, belowWrites := above.all(), below.all()
	require.Equal(t, len(aboveWrites), len(belowWrites), "writes after the ClientHello pass one to one")
	for i := 1; i < len(aboveWrites); i++ {
		require.Equal(t, aboveWrites[i], belowWrites[i], "write %d is not changed", i)
	}
}

// tlshello with a delay: every record is its own write (its own TCP segment).
func TestBPNFragmentTLSHelloDelayed(t *testing.T) {
	addr := startTLSEcho(t)
	conn, above, below := handshake(t, addr, mustParse(t, Options{Packets: "tlshello", Length: "40-60", Delay: "1"}))
	start := time.Now()
	require.NoError(t, conn.Handshake())
	original := above.all()[0]
	wire := below.all()
	pieces := 0
	var joined []byte
	for len(joined) < len(original)-5 {
		parts := records(t, wire[pieces])
		require.Len(t, parts, 1, "one record per write")
		require.LessOrEqual(t, len(parts[0])-5, 60)
		joined = append(joined, parts[0][5:]...)
		pieces++
	}
	require.Equal(t, original[5:], joined)
	require.Greater(t, pieces, 3)
	require.GreaterOrEqual(t, time.Since(start), time.Duration(pieces-1)*time.Millisecond, "pauses between records")
	echoSHA256(t, conn, 64*1024)
}

// packets "1-1": the first write is cut into raw pieces, no new records.
func TestBPNFragmentTCPSegments(t *testing.T) {
	addr := startTLSEcho(t)
	conn, above, below := handshake(t, addr, mustParse(t, Options{Packets: "1-1", Length: "30-50", Delay: "1"}))
	require.NoError(t, conn.Handshake())
	original := above.all()[0]
	wire := below.all()
	var joined []byte
	n := 0
	for len(joined) < len(original) {
		require.LessOrEqual(t, len(wire[n]), 50)
		joined = append(joined, wire[n]...)
		n++
	}
	require.Equal(t, original, joined, "same bytes, only cut")
	require.Len(t, records(t, joined), 1, "record framing is not changed")
	require.Greater(t, n, 3)
	echoSHA256(t, conn, 64*1024)
	require.Equal(t, len(above.all())-1, len(below.all())-n, "later writes pass one to one")
}

func TestBPNFragmentOff(t *testing.T) {
	addr := startTLSEcho(t)
	conn, above, below := handshake(t, addr, nil)
	require.NoError(t, conn.Handshake())
	require.Equal(t, above.all()[0], below.all()[0], "ClientHello goes out in one piece")
	echoSHA256(t, conn, 64*1024)
	require.Equal(t, above.all(), below.all())
}

// A first write that is not a ClientHello is never changed in tlshello mode.
func TestBPNFragmentTLSHelloIgnoresOtherData(t *testing.T) {
	cfg := mustParse(t, Options{Packets: "tlshello", Length: "1-2"})
	for _, first := range [][]byte{
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{22, 3, 1, 0, 10, 2, 0, 0, 6, 0, 0, 0, 0, 0, 0}, // handshake, but ServerHello
		{22, 3, 1, 0, 200, 1, 0, 0, 1},                  // truncated record
		{0, 1, 2, 3, 4, 5, 6},
	} {
		client, server := net.Pipe()
		below := &writeLog{Conn: client}
		conn := NewConn(below, cfg)
		go func() { _, _ = io.Copy(io.Discard, server) }()
		_, err := conn.Write(first)
		require.NoError(t, err)
		_, err = conn.Write(bytes.Repeat([]byte{1}, 100))
		require.NoError(t, err)
		require.Equal(t, [][]byte{first, bytes.Repeat([]byte{1}, 100)}, below.all())
		_ = client.Close()
		_ = server.Close()
	}
}

// The filter model: without fragmentation the middlebox resets the connection,
// with the right mode the handshake and the echo pass through it.
func TestBPNFragmentFilterModel(t *testing.T) {
	addr := startTLSEcho(t)
	cases := []struct {
		filter dpifilter.Mode
		name   string
		opts   *Options
		pass   bool
	}{
		{dpifilter.Record, "off", nil, false},
		{dpifilter.Record, "tlshello-merged", &Options{Packets: "tlshello", Length: "10-20", Delay: "0"}, true},
		{dpifilter.Record, "tlshello-delayed", &Options{Packets: "tlshello", Length: "10-20", Delay: "1"}, true},
		{dpifilter.Record, "tcp-segments", &Options{Packets: "1-1", Length: "10-20", Delay: "5"}, false},
		{dpifilter.Segment, "off", nil, false},
		{dpifilter.Segment, "tlshello-merged", &Options{Packets: "tlshello", Length: "10-20", Delay: "0"}, false},
		{dpifilter.Segment, "tlshello-delayed", &Options{Packets: "tlshello", Length: "100-200", Delay: "5"}, true},
		{dpifilter.Segment, "tcp-segments", &Options{Packets: "1-1", Length: "100-200", Delay: "5"}, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s", tc.filter, tc.name), func(t *testing.T) {
			filter, err := dpifilter.Start(addr, tc.filter)
			require.NoError(t, err)
			t.Cleanup(func() { _ = filter.Close() })
			var cfg *Config
			if tc.opts != nil {
				cfg = mustParse(t, *tc.opts)
			}
			conn, _, _ := handshake(t, filter.Addr(), cfg)
			err = conn.Handshake()
			if !tc.pass {
				require.Error(t, err)
				require.Equal(t, 1, filter.Blocked())
				return
			}
			require.NoError(t, err)
			require.Equal(t, 0, filter.Blocked())
			echoSHA256(t, conn, 256*1024)
		})
	}
}
