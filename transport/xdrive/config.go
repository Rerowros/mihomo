package xdrive

import (
	"fmt"
	"strings"
	"time"
)

const (
	DefaultSegmentBytes    = 512 * 1024
	DefaultFlushInterval   = 20 * time.Millisecond
	DefaultMinPollInterval = 50 * time.Millisecond
	DefaultMaxPollInterval = 500 * time.Millisecond
	DefaultEagerWindow     = 2 * time.Second
	DefaultHoleTimeout     = 30 * time.Second
	DefaultSessionTTL      = 5 * time.Minute
	DefaultConcurrency     = 8

	MaxSegmentBytes = 16 * 1024 * 1024
	MaxConcurrency  = 64
)

// Config is the xdrive transport configuration. It is the same protocol as
// Xray-core transport/internet/xdrive: a byte stream is split into numbered
// segment objects in a folder of a cloud storage, and both peers poll that
// folder. Names and sequencing are part of the wire protocol; see xdrive.go.
type Config struct {
	// Service is "local", "google-drive" or "template".
	Service string
	// RemoteFolder is a directory path (local), a Google Drive folder id, or
	// the {folder} variable of a template.
	RemoteFolder string
	// Secrets are service credentials: client id, client secret and refresh
	// token for Google Drive; free-form {secretN} variables for a template.
	Secrets []string
	// Template is the JSON storage template used by the "template" service.
	Template string

	SegmentBytes    int
	FlushInterval   time.Duration
	PollInterval    time.Duration
	MaxPollInterval time.Duration
	EagerWindow     time.Duration
	HoleTimeout     time.Duration
	SessionTTL      time.Duration
	Concurrency     int
}

func (c *Config) normalized() (params, error) {
	if c == nil {
		return params{}, fmt.Errorf("xdrive: empty config")
	}
	p := params{
		segmentBytes:    c.SegmentBytes,
		flushInterval:   c.FlushInterval,
		minPollInterval: c.PollInterval,
		maxPollInterval: c.MaxPollInterval,
		eagerWindow:     c.EagerWindow,
		holeTimeout:     c.HoleTimeout,
		sessionTTL:      c.SessionTTL,
		concurrency:     c.Concurrency,
	}
	if p.segmentBytes == 0 {
		p.segmentBytes = DefaultSegmentBytes
	}
	if p.segmentBytes > MaxSegmentBytes {
		p.segmentBytes = MaxSegmentBytes
	}
	if p.segmentBytes < 1024 {
		return params{}, fmt.Errorf("xdrive: segment-bytes must be at least 1024")
	}
	if p.flushInterval == 0 {
		p.flushInterval = DefaultFlushInterval
	}
	if p.minPollInterval == 0 {
		p.minPollInterval = DefaultMinPollInterval
	}
	if p.maxPollInterval == 0 {
		p.maxPollInterval = DefaultMaxPollInterval
	}
	if p.maxPollInterval < p.minPollInterval {
		p.maxPollInterval = p.minPollInterval
	}
	if p.eagerWindow == 0 {
		p.eagerWindow = DefaultEagerWindow
	}
	if p.holeTimeout == 0 {
		p.holeTimeout = DefaultHoleTimeout
	}
	if p.sessionTTL == 0 {
		p.sessionTTL = DefaultSessionTTL
	}
	if p.concurrency == 0 {
		p.concurrency = DefaultConcurrency
	}
	if p.concurrency > MaxConcurrency {
		p.concurrency = MaxConcurrency
	}
	if p.concurrency < 1 {
		p.concurrency = 1
	}
	if strings.TrimSpace(c.Service) == "" {
		return params{}, fmt.Errorf("xdrive: empty service")
	}
	return p, nil
}

type params struct {
	segmentBytes    int
	flushInterval   time.Duration
	minPollInterval time.Duration
	maxPollInterval time.Duration
	eagerWindow     time.Duration
	holeTimeout     time.Duration
	sessionTTL      time.Duration
	concurrency     int
}
