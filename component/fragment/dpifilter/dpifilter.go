// Package dpifilter is a test-only model of a middlebox that resets a TCP
// connection when it can read a whole TLS ClientHello with SNI (BadVPN P19).
// It sits between a client and an upstream address on loopback.
package dpifilter

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
)

type Mode int

const (
	// Record reassembles the TCP stream up to the end of the first TLS record
	// and blocks when that single record holds a whole ClientHello with SNI.
	Record Mode = iota
	// Segment looks only at the first chunk the kernel hands over (one read on
	// loopback ≈ one write of the client) and blocks when the TLS records in
	// it, joined together, hold a whole ClientHello with SNI.
	Segment
)

func (m Mode) String() string {
	if m == Segment {
		return "segment"
	}
	return "record"
}

type Filter struct {
	listener net.Listener
	upstream string
	mode     Mode
	blocked  atomic.Int32
	passed   atomic.Int32
}

// Start listens on 127.0.0.1 and forwards accepted connections to upstream.
func Start(upstream string, mode Mode) (*Filter, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &Filter{listener: listener, upstream: upstream, mode: mode}
	go f.serve()
	return f, nil
}

func (f *Filter) Addr() string { return f.listener.Addr().String() }

func (f *Filter) Blocked() int { return int(f.blocked.Load()) }

func (f *Filter) Passed() int { return int(f.passed.Load()) }

func (f *Filter) Close() error { return f.listener.Close() }

func (f *Filter) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *Filter) handle(client net.Conn) {
	defer client.Close()
	var head []byte
	var block bool
	switch f.mode {
	case Segment:
		buf := make([]byte, 64*1024)
		n, err := client.Read(buf)
		if err != nil {
			return
		}
		head = buf[:n]
		block = hasClientHelloWithSNI(joinHandshake(head))
	default:
		header := make([]byte, 5)
		if _, err := io.ReadFull(client, header); err != nil {
			return
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(client, payload); err != nil {
			return
		}
		head = append(header, payload...)
		block = header[0] == 22 && hasClientHelloWithSNI(payload)
	}
	if block {
		f.blocked.Add(1)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0) // RST, like a real middlebox
		}
		return
	}
	f.passed.Add(1)
	server, err := net.Dial("tcp", f.upstream)
	if err != nil {
		return
	}
	defer server.Close()
	if _, err := server.Write(head); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(server, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, server); done <- struct{}{} }()
	<-done
}

// joinHandshake concatenates the payloads of the whole handshake records at
// the start of b.
func joinHandshake(b []byte) []byte {
	var out []byte
	for len(b) >= 5 && b[0] == 22 {
		n := int(binary.BigEndian.Uint16(b[3:]))
		if len(b) < 5+n {
			break
		}
		out = append(out, b[5:5+n]...)
		b = b[5+n:]
	}
	return out
}

// hasClientHelloWithSNI reports whether hs starts with a complete ClientHello
// handshake message that carries a server_name extension.
func hasClientHelloWithSNI(hs []byte) bool {
	if len(hs) < 4 || hs[0] != 1 {
		return false
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return false
	}
	body := hs[4 : 4+n]
	skip := func(k, lenBytes int) bool {
		if len(body) < k {
			return false
		}
		body = body[k:]
		if lenBytes == 0 {
			return true
		}
		if len(body) < lenBytes {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(body[i])
		}
		if len(body) < lenBytes+l {
			return false
		}
		body = body[lenBytes+l:]
		return true
	}
	// version + random, session id, cipher suites, compression methods
	if !skip(34, 0) || !skip(0, 1) || !skip(0, 2) || !skip(0, 1) || len(body) < 2 {
		return false
	}
	ext := body[2:]
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext)
		l := int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+l {
			return false
		}
		if typ == 0 {
			return true
		}
		ext = ext[4+l:]
	}
	return false
}
