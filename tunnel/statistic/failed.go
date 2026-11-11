package statistic

import (
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"

	"github.com/gofrs/uuid/v5"
)

// DefaultFailedLimit bounds how many failed connection attempts are retained in memory.
const DefaultFailedLimit = 256

// FailedConnection records an outbound connection attempt that failed before a
// live tracker could be created. Field names match TrackerInfo so controller
// consumers and history views can process both shapes uniformly.
type FailedConnection struct {
	UUID          uuid.UUID   `json:"id"`
	Metadata      *C.Metadata `json:"metadata"`
	Start         time.Time   `json:"start"`
	Chain         C.Chain     `json:"chains"`
	ProviderChain C.Chain     `json:"providerChains"`
	Rule          string      `json:"rule"`
	RulePayload   string      `json:"rulePayload"`
	Error         string      `json:"error"`
	DurationMs    int64       `json:"durationMs"`
}

// FailedSnapshot is the response payload of GET /connections/failed.
type FailedSnapshot struct {
	FailedTotal int64               `json:"failedTotal"`
	Connections []*FailedConnection `json:"connections"`
}

// SanitizeFailedMetadata clones metadata and strips inbound user identity so
// failed-connection records never expose per-user credentials or session IDs.
func SanitizeFailedMetadata(metadata *C.Metadata) *C.Metadata {
	if metadata == nil {
		return nil
	}
	cloned := metadata.Clone()
	cloned.InUser = ""
	cloned.InSession = nil
	return cloned
}

// NewFailedConnection constructs a sanitized FailedConnection record.
func NewFailedConnection(
	metadata *C.Metadata,
	start time.Time,
	chains C.Chain,
	providerChains C.Chain,
	rule C.Rule,
	err error,
	duration time.Duration,
) *FailedConnection {
	if start.IsZero() {
		start = time.Now()
	}
	var ruleName, rulePayload string
	if rule != nil {
		ruleName = rule.RuleType().String()
		rulePayload = rule.Payload()
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	ms := duration.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	return &FailedConnection{
		UUID:          utils.NewUUIDV4(),
		Metadata:      SanitizeFailedMetadata(metadata),
		Start:         start,
		Chain:         chains,
		ProviderChain: providerChains,
		Rule:          ruleName,
		RulePayload:   rulePayload,
		Error:         errMsg,
		DurationMs:    ms,
	}
}

// RecordFailed stores a failed connection in the bounded ring buffer, bumps the
// cumulative counter, and publishes a dial.error event if any subscriber listens.
func (m *Manager) RecordFailed(fc *FailedConnection) {
	if fc == nil {
		return
	}
	m.failedTotal.Add(1)

	m.failedMu.Lock()
	limit := m.failedLimit
	if limit <= 0 {
		limit = DefaultFailedLimit
	}
	if len(m.failedRing) != limit {
		m.failedRing = make([]*FailedConnection, limit)
		m.failedHead = 0
		m.failedCount = 0
	}
	idx := (m.failedHead + m.failedCount) % limit
	if m.failedCount < limit {
		m.failedRing[idx] = fc
		m.failedCount++
	} else {
		m.failedRing[m.failedHead] = fc
		m.failedHead = (m.failedHead + 1) % limit
	}
	m.failedMu.Unlock()

	if eventbus.Enabled(eventbus.TypeDialError) {
		var netName, src, dst, host, proc string
		if md := fc.Metadata; md != nil {
			netName = md.NetWork.String()
			src = md.SourceAddress()
			dst = md.RemoteAddress()
			host = md.Host
			if host == "" {
				host = md.SniffHost
			}
			proc = md.Process
		}
		chains := make([]string, len(fc.Chain))
		copy(chains, fc.Chain)
		eventbus.Publish(eventbus.TypeDialError, eventbus.DialError{
			ID:          fc.UUID.String(),
			Network:     netName,
			Source:      src,
			Destination: dst,
			Host:        host,
			Process:     proc,
			Chains:      chains,
			Rule:        fc.Rule,
			RulePayload: fc.RulePayload,
			Error:       fc.Error,
			DurationMs:  fc.DurationMs,
		})
	}
}

// FailedConnections returns recorded failed connections ordered oldest to newest.
// If max > 0 and fewer than the stored count, the newest max entries are returned.
func (m *Manager) FailedConnections(max int) []*FailedConnection {
	m.failedMu.Lock()
	defer m.failedMu.Unlock()

	if m.failedCount == 0 || len(m.failedRing) == 0 {
		return []*FailedConnection{}
	}
	limit := len(m.failedRing)
	take := m.failedCount
	startOffset := 0
	if max > 0 && max < take {
		startOffset = take - max
		take = max
	}
	out := make([]*FailedConnection, take)
	for i := 0; i < take; i++ {
		out[i] = m.failedRing[(m.failedHead+startOffset+i)%limit]
	}
	return out
}

// FailedTotal returns the cumulative number of failed connection attempts since
// start or the last ResetStatistic call.
func (m *Manager) FailedTotal() int64 {
	return m.failedTotal.Load()
}

// FailedSnapshot returns the snapshot served by GET /connections/failed.
func (m *Manager) FailedSnapshot(max int) *FailedSnapshot {
	return &FailedSnapshot{
		FailedTotal: m.failedTotal.Load(),
		Connections: m.FailedConnections(max),
	}
}

// ClearFailed clears the stored failed-connection ring buffer without resetting
// the cumulative counter.
func (m *Manager) ClearFailed() {
	m.failedMu.Lock()
	for i := range m.failedRing {
		m.failedRing[i] = nil
	}
	m.failedHead = 0
	m.failedCount = 0
	m.failedMu.Unlock()
}
