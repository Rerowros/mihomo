package xdrive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var errNotFound = errors.New("object not found")

// Entry is one object listed under a prefix. Inline carries the data when the
// storage returns it together with the listing (Google Drive keeps small
// objects in the file description).
type Entry struct {
	Name   string
	Inline []byte
}

// Storage is a flat key-value store with directory-like prefixes, which both
// peers of a session use to exchange segments. Implementations must be safe
// for concurrent use.
type Storage interface {
	Put(ctx context.Context, name string, data []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, prefix string) ([]Entry, error)
	Close() error
}

func newStorage(config *Config) (Storage, error) {
	switch config.Service {
	case "local":
		return newLocalStorage(config.RemoteFolder)
	case "google-drive", "Google Drive":
		return newDriveStorage(config)
	case "template":
		return newTemplateStorage(config)
	default:
		return nil, fmt.Errorf("xdrive: unsupported service %q", config.Service)
	}
}

var (
	sharedMu sync.Mutex
	shared   = make(map[string]Storage)
)

func shareKey(config *Config) string {
	parts := []string{config.Service, config.RemoteFolder}
	parts = append(parts, config.Secrets...)
	parts = append(parts, config.Template)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// sharedStorage returns one storage per service/folder/credentials, so that
// sessions of one client or server share the access token, the id cache and
// the HTTP connection pool.
func sharedStorage(config *Config) (Storage, error) {
	key := shareKey(config)

	sharedMu.Lock()
	defer sharedMu.Unlock()

	if storage, ok := shared[key]; ok {
		return storage, nil
	}
	storage, err := newStorage(config)
	if err != nil {
		return nil, err
	}
	shared[key] = storage
	return storage, nil
}

// ResetSharedStorage forgets every storage instance. Tests use it to isolate
// runs; production code never needs it.
func ResetSharedStorage() {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	for _, storage := range shared {
		_ = storage.Close()
	}
	shared = make(map[string]Storage)
}
