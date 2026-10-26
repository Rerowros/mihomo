package statistic

import "testing"

func TestInboundManager(t *testing.T) {
	manager := &InboundManager{inbounds: make(map[string]*inboundCounters)}
	manager.PushUploaded("in", 10)
	manager.PushDownloaded("in", 20)

	stats := manager.Snapshot()
	if len(stats) != 1 || stats[0].Upload != 10 || stats[0].Download != 20 {
		t.Fatalf("snapshot = %+v", stats)
	}

	upload, download, found := manager.ResetTraffic("in", true, false)
	if !found || upload != 10 || download != 20 {
		t.Fatalf("reset uplink = %d/%d found=%v", upload, download, found)
	}
	if upload, download, _ = manager.ResetTraffic("in", false, false); upload != 0 || download != 20 {
		t.Fatalf("after directional reset = %d/%d", upload, download)
	}
	if _, _, found := manager.ResetTraffic("missing", true, true); found {
		t.Fatal("missing inbound reported as found")
	}
}
