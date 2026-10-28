package metrics

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sample is one parsed line of the exposition format.
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

// parse checks the text exposition format strictly enough for Prometheus:
// every family has HELP then TYPE before its samples, the names are valid,
// labels are quoted and every value is a number. It returns the samples.
func parse(t *testing.T, text string) []sample {
	t.Helper()
	var samples []sample
	typed := map[string]string{}
	helped := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		l := sc.Text()
		require.NotEmpty(t, l, "line %d is empty", line)
		if rest, ok := strings.CutPrefix(l, "# HELP "); ok {
			name, _, _ := strings.Cut(rest, " ")
			require.False(t, helped[name], "line %d: second HELP of %s", line, name)
			helped[name] = true
			continue
		}
		if rest, ok := strings.CutPrefix(l, "# TYPE "); ok {
			name, typ, _ := strings.Cut(rest, " ")
			require.True(t, helped[name], "line %d: TYPE of %s before HELP", line, name)
			require.Contains(t, []string{"counter", "gauge", "histogram"}, typ, "line %d", line)
			typed[name] = typ
			continue
		}
		require.False(t, strings.HasPrefix(l, "#"), "line %d: unknown comment", line)
		s := sample{labels: map[string]string{}}
		var valueText string
		if i := strings.IndexByte(l, '{'); i >= 0 {
			s.name = l[:i]
			end := strings.LastIndexByte(l, '}')
			require.Greater(t, end, i, "line %d", line)
			for _, pair := range splitLabels(t, l[i+1:end]) {
				k, v, ok := strings.Cut(pair, "=")
				require.True(t, ok, "line %d: label %q", line, pair)
				unq, err := strconv.Unquote(v)
				require.NoError(t, err, "line %d: label value %s", line, v)
				s.labels[k] = unq
			}
			valueText = strings.TrimPrefix(l[end+1:], " ")
		} else {
			name, value, ok := strings.Cut(l, " ")
			require.True(t, ok, "line %d", line)
			s.name, valueText = name, value
		}
		require.Regexp(t, `^[a-zA-Z_:][a-zA-Z0-9_:]*$`, s.name, "line %d", line)
		require.NotEmpty(t, typed[s.name], "line %d: sample of %s without TYPE", line, s.name)
		v, err := strconv.ParseFloat(valueText, 64)
		require.NoError(t, err, "line %d: value %q", line, valueText)
		s.value = v
		samples = append(samples, s)
	}
	require.NoError(t, sc.Err())
	return samples
}

// splitLabels splits `a="x",b="y,z"` on the commas outside the quotes.
func splitLabels(t *testing.T, s string) []string {
	var out []string
	inQuote, escaped, start := false, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	require.False(t, inQuote, "unterminated label value in %q", s)
	return append(out, s[start:])
}

func find(samples []sample, name string, labels ...string) (float64, bool) {
next:
	for _, s := range samples {
		if s.name != name {
			continue
		}
		for i := 0; i+1 < len(labels); i += 2 {
			if s.labels[labels[i]] != labels[i+1] {
				continue next
			}
		}
		return s.value, true
	}
	return 0, false
}

func scrape(t *testing.T, o Options) []sample {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, Write(&buf, o))
	return parse(t, buf.String())
}

func TestWriteFormatAndProcess(t *testing.T) {
	samples := scrape(t, Options{Enable: true})
	for _, name := range []string{"mihomo_build_info", "mihomo_uptime_seconds", "mihomo_resident_memory_bytes",
		"mihomo_memory_limit_bytes", "mihomo_live", "mihomo_ready", "mihomo_connections",
		"mihomo_upload_bytes_total", "mihomo_download_bytes_total"} {
		_, ok := find(samples, name)
		assert.True(t, ok, name)
	}
	up, down := statistic.DefaultManager.Total()
	v, _ := find(samples, "mihomo_upload_bytes_total")
	assert.GreaterOrEqual(t, v, float64(up))
	v, _ = find(samples, "mihomo_download_bytes_total")
	assert.GreaterOrEqual(t, v, float64(down))
}

// The per-user and per-inbound series are counters: a panel that polls the
// traffic with reset (REST ?reset, Xray QueryStats reset) must not lower them.
func TestUserAndInboundSeriesSurviveResets(t *testing.T) {
	const inbound = "metrics-test-in"
	alice := statistic.UserKey{Inbound: inbound, User: `al"ice`}
	bob := statistic.UserKey{Inbound: inbound, User: "bob"}
	users := statistic.DefaultUserManager
	users.Open(alice)
	defer users.Close(alice)
	users.PushUploaded(alice, 100)
	users.PushDownloaded(alice, 1000)
	users.PushUploaded(bob, 7)
	statistic.DefaultInboundManager.PushUploaded(inbound, 107)
	statistic.DefaultInboundManager.PushDownloaded(inbound, 1000)

	// a panel drains everything
	users.Snapshot(inbound, "", true)
	users.ResetTraffic(inbound, "bob", true, true)
	statistic.DefaultInboundManager.ResetTraffic(inbound, true, true)
	users.PushUploaded(alice, 1)
	statistic.DefaultInboundManager.PushUploaded(inbound, 1)

	samples := scrape(t, Options{Enable: true, PerUser: true})
	check := func(name string, want float64, labels ...string) {
		t.Helper()
		v, ok := find(samples, name, labels...)
		require.True(t, ok, "%s %v", name, labels)
		assert.Equal(t, want, v, "%s %v", name, labels)
	}
	check("mihomo_user_upload_bytes_total", 101, "inbound", inbound, "user", `al"ice`)
	check("mihomo_user_download_bytes_total", 1000, "inbound", inbound, "user", `al"ice`)
	check("mihomo_user_connections", 1, "inbound", inbound, "user", `al"ice`)
	check("mihomo_user_upload_bytes_total", 7, "inbound", inbound, "user", "bob")
	check("mihomo_user_connections", 0, "inbound", inbound, "user", "bob")
	check("mihomo_inbound_upload_bytes_total", 108, "inbound", inbound)
	check("mihomo_inbound_download_bytes_total", 1000, "inbound", inbound)
	check("mihomo_inbound_users_online", 1, "inbound", inbound)

	// the panel view is still the drained one
	stats := users.Snapshot(inbound, "bob", false)
	require.Len(t, stats, 1)
	assert.Zero(t, stats[0].Upload)

	// without metrics.per-user there is no series of a single user
	samples = scrape(t, Options{Enable: true})
	_, ok := find(samples, "mihomo_user_upload_bytes_total")
	assert.False(t, ok)
	_, ok = find(samples, "mihomo_inbound_users_online", "inbound", inbound)
	assert.True(t, ok)
}

func TestLimitRejectionsCounted(t *testing.T) {
	key := statistic.UserKey{Inbound: "metrics-limit-in", User: "carol"}
	limits := statistic.DefaultLimitManager
	limits.Set(statistic.UserLimit{Inbound: key.Inbound, User: key.User, MaxConns: 1})
	defer limits.Delete(key.Inbound, key.User)

	before, _ := find(scrape(t, Options{Enable: true}), "mihomo_user_limit_rejections_total", "reason", statistic.RejectMaxConns)
	admission, err := limits.Admit(key)
	require.NoError(t, err)
	defer admission.Release()
	_, err = limits.Admit(key)
	require.ErrorIs(t, err, statistic.ErrUserMaxConns)

	after, ok := find(scrape(t, Options{Enable: true}), "mihomo_user_limit_rejections_total", "reason", statistic.RejectMaxConns)
	require.True(t, ok)
	assert.Equal(t, before+1, after)
}

func TestLabelEscaping(t *testing.T) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	w := newWriter(bw)
	w.family("x_total", "counter", "a\\b\nc")
	w.int("x_total", 3, "l", "q\"\\\n")
	require.NoError(t, bw.Flush())
	assert.Equal(t, "# HELP x_total a\\\\b\\nc\n# TYPE x_total counter\nx_total{l=\"q\\\"\\\\\\n\"} 3\n", buf.String())
	samples := parse(t, buf.String())
	require.Len(t, samples, 1)
	assert.Equal(t, "q\"\\\n", samples[0].labels["l"])
}

// A user name with bytes that are not UTF-8 must not break the scrape:
// Prometheus rejects the whole exposition on an invalid label value.
func TestLabelInvalidUTF8(t *testing.T) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	w := newWriter(bw)
	w.family("x_total", "counter", "x")
	w.int("x_total", 1, "user", "a\xffb\xc3", "inbound", "ok\"\xfe")
	require.NoError(t, bw.Flush())
	assert.True(t, utf8.Valid(buf.Bytes()), "%q", buf.String())
	assert.Equal(t, "# HELP x_total x\n# TYPE x_total counter\nx_total{user=\"a�b�\",inbound=\"ok\\\"�\"} 1\n", buf.String())
}
