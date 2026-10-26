package xdrive

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

// serviceStall ends a request that makes no progress for the given time: no
// answer after the body went out, or no byte of either body. A large object on
// a slow link may take minutes and is fine while its bytes move.
const serviceStall = 60 * time.Second

type serviceTransport struct {
	next  http.RoundTripper
	stall time.Duration
}

func newServiceClient(maxConns int) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		MaxConnsPerHost:     maxConns,
		IdleConnTimeout:     5 * time.Minute,
		TLSHandshakeTimeout: 20 * time.Second,
	}
	return &http.Client{Transport: &serviceTransport{next: transport, stall: serviceStall}}
}

func (t *serviceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(r.Context())
	timer := time.AfterFunc(t.stall, func() { cancel(errStalled) })
	alive := func() { timer.Reset(t.stall) }
	end := func() {
		timer.Stop()
		cancel(nil)
	}

	r = r.WithContext(ctx)
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &progressBody{ReadCloser: r.Body, alive: alive}
	}

	resp, err := t.next.RoundTrip(r)
	if err != nil {
		if context.Cause(ctx) == errStalled {
			err = errStalled
		}
		end()
		return nil, err
	}
	alive()
	resp.Body = &progressBody{ReadCloser: resp.Body, alive: alive, end: end, ctx: ctx}
	return resp, nil
}

var errStalled = errStalledError{}

type errStalledError struct{}

func (errStalledError) Error() string { return "the request made no progress" }

type progressBody struct {
	io.ReadCloser
	alive func()
	end   func()
	ctx   context.Context
}

func (b *progressBody) Read(p []byte) (int, error) {
	// http2 reads a request body up to 512 KiB at a time and sends it all
	// before the next read, which on a slow link could look like no progress.
	if len(p) > 16<<10 {
		p = p[:16<<10]
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 && b.alive != nil {
		b.alive()
	}
	if err != nil && err != io.EOF && b.ctx != nil && context.Cause(b.ctx) == errStalled {
		err = errStalled
	}
	return n, err
}

func (b *progressBody) Close() error {
	err := b.ReadCloser.Close()
	if b.end != nil {
		b.end()
	}
	return err
}

// discardBody reads and closes a response body so that the connection can be
// reused.
func discardBody(resp *http.Response) error {
	_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	closeErr := resp.Body.Close()
	if err != nil {
		return err
	}
	return closeErr
}
