package net

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/sing/common/network"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyConn(t *testing.T) {
	payload := make([]byte, 1<<20+123)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	srcR, srcW := io.Pipe()
	dstR, dstW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := copyConn(dstW, srcR)
		_ = dstW.Close()
		done <- err
	}()
	go func() {
		_, _ = srcW.Write(payload)
		_ = srcW.Close()
	}()
	got, err := io.ReadAll(dstR)
	require.NoError(t, err)
	require.NoError(t, <-done)
	assert.Equal(t, len(payload), len(got))
	assert.True(t, bytes.Equal(payload, got))
}

func TestRelay(t *testing.T) {
	client, left := net.Pipe()
	right, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go Relay(left, right)

	payload := []byte("relay payload")
	go func() { _, _ = client.Write(payload) }()
	buf := make([]byte, len(payload))
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadFull(server, buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf)

	go func() { _, _ = server.Write(payload) }()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(client, buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf)
}

func TestReadSizing(t *testing.T) {
	var sizing readSizing
	const small = 1024
	// a read that fills the small buffer switches to full buffers
	sizing.update(small, small)
	assert.True(t, sizing.full)
	// one short read is not enough to shrink (Shadowsocks alternates)
	sizing.update(100, small)
	assert.True(t, sizing.full)
	sizing.update(100, small)
	assert.False(t, sizing.full)
	// a small read after shrinking keeps the small buffer
	sizing.update(100, small)
	assert.False(t, sizing.full)
}

func TestSmallReadLen(t *testing.T) {
	assert.Equal(t, smallReadSize, smallReadLen(network.ReadWaitOptions{}))
	assert.Equal(t, 0, smallReadLen(network.ReadWaitOptions{MTU: smallReadSize}))
}
