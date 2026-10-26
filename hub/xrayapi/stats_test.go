package xrayapi

import (
	"testing"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestStatValueAndReset(t *testing.T) {
	key := statistic.UserKey{Inbound: "xray-test-in", User: "xray-test-user"}
	statistic.DefaultUserManager.PushUploaded(key, 100)
	statistic.DefaultUserManager.PushDownloaded(key, 200)
	statistic.DefaultUserManager.Open(key)
	defer statistic.DefaultUserManager.Close(key)
	statistic.DefaultInboundManager.PushUploaded("xray-test-in", 100)
	statistic.DefaultInboundManager.PushDownloaded("xray-test-in", 200)

	if value, found := statValue("user>>>xray-test-user>>>traffic>>>uplink", false); !found || value != 100 {
		t.Fatalf("user uplink = %d, found = %v", value, found)
	}
	if value, found := statValue("inbound>>>xray-test-in>>>traffic>>>downlink", false); !found || value != 200 {
		t.Fatalf("inbound downlink = %d, found = %v", value, found)
	}
	if value, found := statValue("inbound>>>xray-test-in>>>traffic>>>uplink", true); !found || value != 100 {
		t.Fatalf("reset inbound uplink = %d, found = %v", value, found)
	}
	if value, _ := statValue("user>>>xray-test-user>>>traffic>>>uplink", false); value != 100 {
		t.Fatalf("inbound reset touched user uplink = %d", value)
	}
	if value, found := statValue("user>>>xray-test-user>>>online", false); !found || value != 1 {
		t.Fatalf("online = %d, found = %v", value, found)
	}
	if _, found := statValue("user>>>nobody>>>traffic>>>uplink", false); found {
		t.Fatal("unknown user reported as found")
	}
	if value, found := statValue("user>>>xray-test-user>>>traffic>>>uplink", true); !found || value != 100 {
		t.Fatalf("reset uplink = %d, found = %v", value, found)
	}
	if value, _ := statValue("user>>>xray-test-user>>>traffic>>>uplink", false); value != 0 {
		t.Fatalf("uplink after reset = %d", value)
	}
	if value, _ := statValue("user>>>xray-test-user>>>traffic>>>downlink", false); value != 200 {
		t.Fatalf("downlink reset by uplink read = %d", value)
	}
}

func TestQueryStats(t *testing.T) {
	key := statistic.UserKey{Inbound: "xray-query-in", User: "xray-query-user"}
	statistic.DefaultUserManager.PushUploaded(key, 10)
	statistic.DefaultUserManager.PushDownloaded(key, 20)
	defer statistic.DefaultUserManager.Close(key)

	request := appendString(nil, 1, "xray-query-user")
	response, status, message := queryStats(request)
	if status != 0 {
		t.Fatalf("query stats status = %d: %s", status, message)
	}
	var names []string
	err := walkFields(response, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num != 1 {
			return nil
		}
		return walkFields(b, func(statNum protowire.Number, _ protowire.Type, _ uint64, statValue []byte) error {
			if statNum == 1 {
				names = append(names, string(statValue))
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("names = %v", names)
	}
}

func TestQueryStatsResetReturnsResetValue(t *testing.T) {
	key := statistic.UserKey{Inbound: "xray-query-reset-in", User: "xray-query-reset-user"}
	statistic.DefaultUserManager.PushUploaded(key, 42)
	defer statistic.DefaultUserManager.Close(key)

	request := appendString(nil, 1, "xray-query-reset-user")
	request = appendVarint(request, 2, 1)
	response, status, message := queryStats(request)
	if status != 0 {
		t.Fatalf("query stats status = %d: %s", status, message)
	}
	var got int64 = -1
	err := walkFields(response, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num != 1 {
			return nil
		}
		var name string
		var value int64
		if err := walkFields(b, func(statNum protowire.Number, _ protowire.Type, v uint64, statValue []byte) error {
			switch statNum {
			case 1:
				name = string(statValue)
			case 2:
				value = int64(v)
			}
			return nil
		}); err != nil {
			return err
		}
		if name == "user>>>xray-query-reset-user>>>traffic>>>uplink" {
			got = value
		}
		return nil
	})
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got != 42 {
		t.Fatalf("reset value in response = %d, want 42", got)
	}
	// The reset must have used the value it returned; the counter is now zero.
	if remaining := statistic.DefaultUserManager.Snapshot("", "xray-query-reset-user", false); len(remaining) != 1 || remaining[0].Upload != 0 {
		t.Fatalf("counter after reset = %+v", remaining)
	}
}

func TestGetUsersStats(t *testing.T) {
	key := statistic.UserKey{Inbound: "xray-users-in", User: "xray-users-user"}
	statistic.DefaultUserManager.PushUploaded(key, 7)
	statistic.DefaultUserManager.PushDownloaded(key, 9)
	defer statistic.DefaultUserManager.Close(key)

	var request []byte
	request = appendVarint(request, 1, 1)
	response, status, message := getUsersStats(request)
	if status != 0 {
		t.Fatalf("get users stats status = %d: %s", status, message)
	}
	var emails []string
	err := walkFields(response, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num != 1 {
			return nil
		}
		return walkFields(b, func(statNum protowire.Number, _ protowire.Type, _ uint64, email []byte) error {
			if statNum == 1 {
				emails = append(emails, string(email))
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("decode users stats: %v", err)
	}
	found := false
	for _, email := range emails {
		if email == "xray-users-user" {
			found = true
		}
	}
	if !found {
		t.Fatalf("emails = %v", emails)
	}
}
