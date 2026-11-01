// Package fragment splits the first TLS ClientHello (or the first raw writes)
// of an outgoing TCP connection, so that a middlebox that parses a whole
// ClientHello from one record or one segment cannot read it (BadVPN P19).
//
// The behaviour follows Xray-core finalmask "fragment"
// (transport/internet/finalmask/fragment/conn.go, Xray-core v26.10.21, MPL-2.0):
//
//   - packets "tlshello": the first write, if it is a whole TLS handshake
//     record, is re-framed into several TLS records with `length` bytes of
//     payload each. With delay "0" all records go out in one write (the
//     kernel then segments by MSS as usual); with a non-zero delay every record
//     is a separate write followed by a pause.
//   - packets "N-M": writes number N..M of the connection are cut into raw
//     pieces of `length` bytes (TCP segments, no re-framing), with a pause
//     between pieces.
//
// Everything after that is passed through untouched.
package fragment

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/randv2"
)

const (
	recordHeaderLen       = 5
	recordTypeHandshake   = 22
	handshakeClientHello  = 1
	maxTLSPlaintextLength = 16384
)

// Options is the proxy-level `fragment-opts` block. Names and values mirror
// the Xray finalmask fragment settings (`packets`, `length`, `delay`,
// `maxSplit`), so a subscription can carry the same values as an Xray `fm`
// parameter.
type Options struct {
	Packets  string `proxy:"packets,omitempty"`
	Length   string `proxy:"length,omitempty"`
	Delay    string `proxy:"delay,omitempty"`
	MaxSplit string `proxy:"max-split,omitempty"`
}

type rng struct{ min, max int }

func (r rng) rand() int {
	if r.max <= r.min {
		return r.min
	}
	return r.min + randv2.IntN(r.max-r.min+1)
}

func parseRange(name, s, fallback string) (rng, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = fallback
	}
	lo, hi, found := strings.Cut(s, "-")
	minVal, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return rng{}, fmt.Errorf("fragment-opts.%s: invalid range %q", name, s)
	}
	maxVal := minVal
	if found {
		if maxVal, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
			return rng{}, fmt.Errorf("fragment-opts.%s: invalid range %q", name, s)
		}
	}
	if maxVal < minVal { // Xray swaps a reversed range too
		minVal, maxVal = maxVal, minVal
	}
	if minVal < 0 || maxVal > math.MaxInt32 {
		return rng{}, fmt.Errorf("fragment-opts.%s: invalid range %q", name, s)
	}
	return rng{minVal, maxVal}, nil
}

// Config is the parsed form of Options. A nil *Config means "off".
type Config struct {
	tlsHello  bool
	packetsLo int
	packetsHi int
	length    rng
	delay     rng
	maxSplit  rng
}

// Parse returns nil, nil when the block is empty (fragmentation off).
func (o Options) Parse() (*Config, error) {
	if o == (Options{}) {
		return nil, nil
	}
	c := &Config{}
	switch p := strings.ToLower(strings.TrimSpace(o.Packets)); p {
	case "", "tlshello":
		c.tlsHello = true
	default:
		r, err := parseRange("packets", p, "")
		if err != nil {
			return nil, err
		}
		if r.min == 0 {
			return nil, errors.New(`fragment-opts.packets: must be "tlshello" or a range starting from 1`)
		}
		c.packetsLo, c.packetsHi = r.min, r.max
	}
	var err error
	if c.length, err = parseRange("length", o.Length, "10-20"); err != nil {
		return nil, err
	}
	if c.length.min == 0 {
		return nil, errors.New("fragment-opts.length: minimum can't be 0")
	}
	if c.delay, err = parseRange("delay", o.Delay, "0"); err != nil {
		return nil, err
	}
	if c.maxSplit, err = parseRange("max-split", o.MaxSplit, "0"); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) sleep() {
	if c.delay.max > 0 {
		time.Sleep(time.Duration(c.delay.rand()) * time.Millisecond)
	}
}

// NewConn wraps an outgoing TCP connection. A nil config returns conn as is.
func NewConn(conn net.Conn, c *Config) net.Conn {
	if c == nil {
		return conn
	}
	return &Conn{Conn: conn, config: c}
}

type Conn struct {
	net.Conn
	config *Config
	count  int
	done   bool
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	c.count++
	cfg := c.config
	if cfg.tlsHello {
		c.done = true
		if c.count == 1 {
			if recordLen, ok := clientHelloRecordLen(p); ok {
				return c.writeHello(p, recordLen)
			}
		}
		return c.Conn.Write(p)
	}
	if c.count >= cfg.packetsHi {
		c.done = true
	}
	if c.count < cfg.packetsLo {
		return c.Conn.Write(p)
	}
	return c.writeSplit(p)
}

// clientHelloRecordLen reports the full length of the first TLS record in p
// when p starts with a whole handshake record that carries a ClientHello.
func clientHelloRecordLen(p []byte) (int, bool) {
	if len(p) <= recordHeaderLen || p[0] != recordTypeHandshake || p[1] != 3 || p[5] != handshakeClientHello {
		return 0, false
	}
	n := int(p[3])<<8 | int(p[4])
	if n > maxTLSPlaintextLength || len(p) < recordHeaderLen+n {
		return 0, false
	}
	return recordHeaderLen + n, true
}

func (c *Conn) writeHello(p []byte, recordLen int) (int, error) {
	cfg := c.config
	data := p[recordHeaderLen:recordLen]
	merge := cfg.delay.max == 0
	maxSplit := cfg.maxSplit.rand()
	var out []byte
	if merge {
		out = make([]byte, 0, len(data)+(len(data)/cfg.length.min+1)*recordHeaderLen)
	}
	for from, split := 0, 1; from < len(data); split++ {
		to := from + cfg.length.rand()
		if to > len(data) || (maxSplit > 0 && split >= maxSplit) {
			to = len(data)
		}
		l := to - from
		record := make([]byte, 0, recordHeaderLen+l)
		record = append(record, p[0], p[1], p[2], byte(l>>8), byte(l))
		record = append(record, data[from:to]...)
		from = to
		if merge {
			out = append(out, record...)
			continue
		}
		if _, err := c.Conn.Write(record); err != nil {
			return 0, err
		}
		if from < len(data) {
			cfg.sleep()
		}
	}
	if merge {
		if _, err := c.Conn.Write(out); err != nil {
			return 0, err
		}
	}
	if len(p) > recordLen {
		n, err := c.Conn.Write(p[recordLen:])
		return recordLen + n, err
	}
	return len(p), nil
}

func (c *Conn) writeSplit(p []byte) (int, error) {
	cfg := c.config
	maxSplit := cfg.maxSplit.rand()
	from := 0
	for split := 1; from < len(p); split++ {
		to := from + cfg.length.rand()
		if to > len(p) || (maxSplit > 0 && split >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		if from < len(p) {
			cfg.sleep()
		}
	}
	return from, nil
}

func (c *Conn) Upstream() any { return c.Conn }

func (c *Conn) ReaderReplaceable() bool { return true }

func (c *Conn) WriterReplaceable() bool { return c.done }

var _ N.ReaderWithUpstream = (*Conn)(nil)

// Dialer wraps the TCP connections of a proxy dialer. UDP is untouched.
type Dialer struct {
	C.Dialer
	Config *Config
}

// NewDialer returns d as is when the config is nil (fragmentation off).
func NewDialer(d C.Dialer, c *Config) C.Dialer {
	if c == nil {
		return d
	}
	return Dialer{Dialer: d, Config: c}
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil || !strings.HasPrefix(network, "tcp") {
		return conn, err
	}
	return NewConn(conn, d.Config), nil
}
