package xrayapi

import (
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"google.golang.org/protobuf/encoding/protowire"
)

var processStart = time.Now()

func getStats(message []byte) ([]byte, int, string) {
	name, reset, err := decodeGetStats(message)
	if err != nil {
		return nil, 3, err.Error()
	}
	value, found := statValue(name, reset)
	if !found {
		return nil, 5, name + " not found."
	}
	return appendMessage(nil, 1, encodeStat(name, value)), 0, ""
}

func statValue(name string, reset bool) (int64, bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) == 4 && parts[2] == "traffic" {
		switch parts[0] {
		case "user":
			upload, download, found := statistic.DefaultUserManager.ResetTraffic("", parts[1], reset && parts[3] == "uplink", reset && parts[3] == "downlink")
			if !found {
				return 0, false
			}
			if parts[3] == "uplink" {
				return upload, true
			}
			if parts[3] == "downlink" {
				return download, true
			}
		case "inbound":
			upload, download, found := statistic.DefaultInboundManager.ResetTraffic(parts[1], reset && parts[3] == "uplink", reset && parts[3] == "downlink")
			if !found {
				return 0, false
			}
			if parts[3] == "uplink" {
				return upload, true
			}
			if parts[3] == "downlink" {
				return download, true
			}
		}
	}
	if len(parts) == 3 && parts[2] == "online" {
		switch parts[0] {
		case "user":
			_, _, conns, found := sumUsers("", parts[1], false)
			return conns, found
		case "inbound":
			_, _, conns, found := sumUsers(parts[1], "", false)
			return conns, found
		}
	}
	return 0, false
}

func sumUsers(inbound, user string, reset bool) (upload, download, conns int64, found bool) {
	for _, stat := range statistic.DefaultUserManager.Snapshot(inbound, user, reset) {
		upload += stat.Upload
		download += stat.Download
		conns += stat.Conns
		found = true
	}
	return
}

func queryStats(message []byte) ([]byte, int, string) {
	pattern, reset, err := decodeQueryStats(message)
	if err != nil {
		return nil, 3, err.Error()
	}
	entries := collectStats()
	matched := make([]statPair, 0, len(entries))
	for _, entry := range entries {
		if strings.Contains(entry.Name, pattern) {
			matched = append(matched, entry)
		}
	}
	if reset {
		for i, entry := range matched {
			parts := strings.Split(entry.Name, ">>>")
			if len(parts) != 4 || parts[2] != "traffic" {
				continue
			}
			upload := parts[3] == "uplink"
			download := parts[3] == "downlink"
			if !upload && !download {
				continue
			}
			switch parts[0] {
			case "user":
				up, down, found := statistic.DefaultUserManager.ResetTraffic("", parts[1], upload, download)
				if found {
					if upload {
						matched[i].Value = up
					} else {
						matched[i].Value = down
					}
				}
			case "inbound":
				up, down, found := statistic.DefaultInboundManager.ResetTraffic(parts[1], upload, download)
				if found {
					if upload {
						matched[i].Value = up
					} else {
						matched[i].Value = down
					}
				}
			}
		}
	}
	return encodeStatsResponse(matched), 0, ""
}

func collectStats() []statPair {
	type userTotals struct {
		upload   int64
		download int64
	}
	byUser := make(map[string]*userTotals)
	for _, stat := range statistic.DefaultUserManager.Snapshot("", "", false) {
		totals := byUser[stat.User]
		if totals == nil {
			totals = &userTotals{}
			byUser[stat.User] = totals
		}
		totals.upload += stat.Upload
		totals.download += stat.Download
	}
	entries := make([]statPair, 0, 32)
	for user, totals := range byUser {
		if totals.upload > 0 {
			entries = append(entries, statPair{Name: "user>>>" + user + ">>>traffic>>>uplink", Value: totals.upload})
		}
		if totals.download > 0 {
			entries = append(entries, statPair{Name: "user>>>" + user + ">>>traffic>>>downlink", Value: totals.download})
		}
	}
	for _, stat := range statistic.DefaultInboundManager.Snapshot() {
		if stat.Upload > 0 {
			entries = append(entries, statPair{Name: "inbound>>>" + stat.Inbound + ">>>traffic>>>uplink", Value: stat.Upload})
		}
		if stat.Download > 0 {
			entries = append(entries, statPair{Name: "inbound>>>" + stat.Inbound + ">>>traffic>>>downlink", Value: stat.Download})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries
}

func getSysStats(_ []byte) ([]byte, int, string) {
	return encodeSysStats(uint32(time.Since(processStart).Seconds())), 0, ""
}

func getStatsOnline(message []byte) ([]byte, int, string) {
	name, _, err := decodeGetStats(message)
	if err != nil {
		return nil, 3, err.Error()
	}
	value, found := statValue(name, false)
	if !found {
		return nil, 5, name + " not found."
	}
	return appendMessage(nil, 1, encodeStat(name, value)), 0, ""
}

func getStatsOnlineIPList(message []byte) ([]byte, int, string) {
	name, _, err := decodeGetStats(message)
	if err != nil {
		return nil, 3, err.Error()
	}
	if _, found := statValue(name, false); !found {
		return nil, 5, name + " not found."
	}
	return encodeOnlineIPList(name), 0, ""
}

func getAllOnlineUsers(_ []byte) ([]byte, int, string) {
	var users []string
	seen := make(map[string]struct{})
	for _, stat := range statistic.DefaultUserManager.Snapshot("", "", false) {
		if stat.Conns <= 0 {
			continue
		}
		if _, ok := seen[stat.User]; ok {
			continue
		}
		seen[stat.User] = struct{}{}
		users = append(users, "user>>>"+stat.User+">>>online")
	}
	sort.Strings(users)
	return encodeAllOnlineUsers(users), 0, ""
}

func getUsersStats(message []byte) ([]byte, int, string) {
	var includeTraffic, reset bool
	err := walkFields(message, func(num protowire.Number, _ protowire.Type, v uint64, _ []byte) error {
		switch num {
		case 1:
			includeTraffic = v != 0
		case 2:
			reset = v != 0
		}
		return nil
	})
	if err != nil {
		return nil, 3, err.Error()
	}
	byEmail := make(map[string]*userTraffic)
	for _, stat := range statistic.DefaultUserManager.Snapshot("", "", reset) {
		user := byEmail[stat.User]
		if user == nil {
			user = &userTraffic{Email: stat.User}
			byEmail[stat.User] = user
		}
		user.Upload += stat.Upload
		user.Download += stat.Download
	}
	users := make([]userTraffic, 0, len(byEmail))
	for _, user := range byEmail {
		users = append(users, *user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
	return encodeUsersStats(users, includeTraffic), 0, ""
}
