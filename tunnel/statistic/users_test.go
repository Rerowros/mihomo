package statistic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserManager(t *testing.T) {
	manager := &UserManager{users: make(map[UserKey]*userCounters)}
	alice := UserKey{Inbound: "vless-in", User: "alice"}
	bob := UserKey{Inbound: "vless-in", User: "bob"}

	manager.Open(alice)
	manager.Open(alice)
	manager.PushUploaded(alice, 100)
	manager.PushDownloaded(alice, 200)
	manager.Open(bob)
	manager.PushUploaded(bob, 300)

	stats := manager.Snapshot("", "", false)
	assert.Len(t, stats, 2)
	assert.Equal(t, "alice", stats[0].User)
	assert.Equal(t, int64(100), stats[0].Upload)
	assert.Equal(t, int64(200), stats[0].Download)
	assert.Equal(t, int64(2), stats[0].Conns)
	assert.Equal(t, "bob", stats[1].User)

	filtered := manager.Snapshot("vless-in", "alice", false)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "alice", filtered[0].User)
	assert.Empty(t, manager.Snapshot("other", "", false))

	// reset returns the period delta and starts a new period
	reset := manager.Snapshot("vless-in", "alice", true)
	assert.Equal(t, int64(100), reset[0].Upload)
	assert.Equal(t, int64(200), reset[0].Download)
	after := manager.Snapshot("vless-in", "alice", false)
	assert.Equal(t, int64(0), after[0].Upload)
	assert.Equal(t, int64(0), after[0].Download)
	assert.Equal(t, int64(2), after[0].Conns)

	manager.Close(alice)
	assert.Equal(t, int64(1), manager.Snapshot("vless-in", "alice", false)[0].Conns)
}
