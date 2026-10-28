package xrayapi

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"google.golang.org/protobuf/encoding/protowire"
)

// connectFrom opens a connection of key from ip, the way the tunnel admits
// it; the returned func closes it.
func connectFrom(t *testing.T, key statistic.UserKey, ip string) func() {
	t.Helper()
	admission, err := statistic.DefaultLimitManager.AdmitFrom(key, netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("admit %v from %s: %v", key, ip, err)
	}
	return admission.Release
}

func TestStatValueAndReset(t *testing.T) {
	key := statistic.UserKey{Inbound: "xray-test-in", User: "xray-test-user"}
	statistic.DefaultUserManager.PushUploaded(key, 100)
	statistic.DefaultUserManager.PushDownloaded(key, 200)
	defer connectFrom(t, key, "198.51.100.1")()
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
	defer connectFrom(t, key, "198.51.100.3")()

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

// T11: QueryStats returns counters only, like Xray; online is served by
// GetStatsOnline.
func TestQueryStatsHasNoOnline(t *testing.T) {
	key := statistic.UserKey{Inbound: "xray-online-in", User: "xray-online-user"}
	statistic.DefaultUserManager.PushUploaded(key, 5)
	defer connectFrom(t, key, "198.51.100.2")()

	response, status, message := queryStats(nil)
	if status != 0 {
		t.Fatalf("query stats status = %d: %s", status, message)
	}
	err := walkFields(response, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num != 1 {
			return nil
		}
		return walkFields(b, func(statNum protowire.Number, _ protowire.Type, _ uint64, name []byte) error {
			if statNum == 1 && strings.HasSuffix(string(name), ">>>online") {
				t.Errorf("QueryStats returned %s", name)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	_, status, message = getStatsOnline(appendString(nil, 1, "user>>>xray-online-user>>>online"))
	if status != 0 {
		t.Fatalf("GetStatsOnline status = %d: %s", status, message)
	}
	if value, found := statValue("user>>>xray-online-user>>>online", false); !found || value != 1 {
		t.Fatalf("online = %d, found = %v", value, found)
	}
}

type usersStatsUser struct {
	email    string
	ips      map[string]int64
	upload   int64
	download int64
}

func decodeUsersStats(t *testing.T, response []byte) map[string]usersStatsUser {
	t.Helper()
	users := map[string]usersStatsUser{}
	err := walkFields(response, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num != 1 {
			return nil
		}
		user := usersStatsUser{ips: map[string]int64{}}
		err := walkFields(b, func(n protowire.Number, _ protowire.Type, _ uint64, field []byte) error {
			switch n {
			case 1:
				user.email = string(field)
			case 2:
				var ip string
				var seen int64
				if err := walkFields(field, func(n protowire.Number, _ protowire.Type, v uint64, f []byte) error {
					switch n {
					case 1:
						ip = string(f)
					case 2:
						seen = int64(v)
					}
					return nil
				}); err != nil {
					return err
				}
				user.ips[ip] = seen
			case 3:
				return walkFields(field, func(n protowire.Number, _ protowire.Type, v uint64, _ []byte) error {
					switch n {
					case 1:
						user.upload = int64(v)
					case 2:
						user.download = int64(v)
					}
					return nil
				})
			}
			return nil
		})
		users[user.email] = user
		return err
	})
	if err != nil {
		t.Fatalf("decode users stats: %v", err)
	}
	return users
}

// GetUsersStats, like Xray, returns only the online users, with their
// addresses (field 2, IPv6 in brackets, no loopback); a reset zeroes only
// their traffic.
func TestGetUsersStatsOnlineOnly(t *testing.T) {
	online := statistic.UserKey{Inbound: "xray-us-in", User: "xray-us-online"}
	other := statistic.UserKey{Inbound: "xray-us-in2", User: "xray-us-online"}
	offline := statistic.UserKey{Inbound: "xray-us-in", User: "xray-us-offline"}
	local := statistic.UserKey{Inbound: "xray-us-in", User: "xray-us-local"}
	statistic.DefaultUserManager.PushUploaded(online, 3)
	statistic.DefaultUserManager.PushDownloaded(other, 4)
	statistic.DefaultUserManager.PushUploaded(offline, 11)
	defer connectFrom(t, online, "203.0.113.7")()
	defer connectFrom(t, other, "2001:db8::7")()
	defer connectFrom(t, other, "::ffff:203.0.113.7")()
	defer connectFrom(t, local, "127.0.0.1")()
	closeOld := connectFrom(t, offline, "203.0.113.8")
	closeOld()

	request := appendVarint(nil, 1, 1)
	request = appendVarint(request, 2, 1)
	response, status, message := getUsersStats(request)
	if status != 0 {
		t.Fatalf("status = %d: %s", status, message)
	}
	users := decodeUsersStats(t, response)
	if _, ok := users["xray-us-offline"]; ok {
		t.Fatal("offline user returned")
	}
	if _, ok := users["xray-us-local"]; ok {
		t.Fatal("loopback-only user returned as online")
	}
	user, ok := users["xray-us-online"]
	if !ok {
		t.Fatalf("online user missing: %v", users)
	}
	var ips []string
	for ip, seen := range user.ips {
		if seen <= 0 {
			t.Errorf("ip %s lastSeen = %d", ip, seen)
		}
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if strings.Join(ips, ",") != "203.0.113.7,[2001:db8::7]" {
		t.Fatalf("ips = %v", ips)
	}
	if user.upload != 3 || user.download != 4 {
		t.Fatalf("traffic = %d/%d, want 3/4", user.upload, user.download)
	}
	if stats := statistic.DefaultUserManager.Snapshot("xray-us-in", "xray-us-offline", false); len(stats) != 1 || stats[0].Upload != 11 {
		t.Fatalf("reset touched the offline user: %+v", stats)
	}
	if stats := statistic.DefaultUserManager.Snapshot("xray-us-in", "xray-us-online", false); len(stats) != 1 || stats[0].Upload != 0 {
		t.Fatalf("online user not reset: %+v", stats)
	}
}

// GetStatsOnline counts addresses like Xray, GetStatsOnlineIpList returns the
// map ip -> lastSeen (field 2) and GetAllOnlineUsers the users with one.
func TestOnlineIPList(t *testing.T) {
	key := statistic.UserKey{Inbound: "xray-ipl-in", User: "xray-ipl-user"}
	defer connectFrom(t, key, "192.0.2.10")()
	defer connectFrom(t, key, "192.0.2.10")()
	defer connectFrom(t, key, "2001:db8::10")()
	gone := connectFrom(t, key, "192.0.2.11")
	gone()

	name := "user>>>xray-ipl-user>>>online"
	if value, found := statValue(name, false); !found || value != 2 {
		t.Fatalf("online = %d, found = %v, want 2 addresses", value, found)
	}
	response, status, message := getStatsOnlineIPList(appendString(nil, 1, name))
	if status != 0 {
		t.Fatalf("status = %d: %s", status, message)
	}
	var gotName string
	ips := map[string]int64{}
	err := walkFields(response, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		switch num {
		case 1:
			gotName = string(b)
		case 2:
			var ip string
			var seen int64
			if err := walkFields(b, func(n protowire.Number, _ protowire.Type, v uint64, f []byte) error {
				if n == 1 {
					ip = string(f)
				} else if n == 2 {
					seen = int64(v)
				}
				return nil
			}); err != nil {
				return err
			}
			ips[ip] = seen
		}
		return nil
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotName != name || len(ips) != 2 || ips["192.0.2.10"] <= 0 || ips["[2001:db8::10]"] <= 0 {
		t.Fatalf("name = %q, ips = %v", gotName, ips)
	}
	response, _, _ = getAllOnlineUsers(nil)
	found := false
	_ = walkFields(response, func(num protowire.Number, _ protowire.Type, _ uint64, b []byte) error {
		if num == 1 && string(b) == name {
			found = true
		}
		return nil
	})
	if !found {
		t.Fatal("GetAllOnlineUsers misses the user")
	}
}
