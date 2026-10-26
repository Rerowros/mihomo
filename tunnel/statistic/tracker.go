package statistic

import (
	"io"
	"net"
	"sync"
	stdatomic "sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	"github.com/gofrs/uuid/v5"
)

type Tracker interface {
	ID() string
	Close() error
	Info() *TrackerInfo
	C.Connection
}

type TrackerInfo struct {
	UUID          uuid.UUID    `json:"id"`
	Metadata      *C.Metadata  `json:"metadata"`
	UploadTotal   atomic.Int64 `json:"upload"`
	DownloadTotal atomic.Int64 `json:"download"`
	Start         time.Time    `json:"start"`
	Chain         C.Chain      `json:"chains"`
	ProviderChain C.Chain      `json:"providerChains"`
	Rule          string       `json:"rule"`
	RulePayload   string       `json:"rulePayload"`
}

type tcpTracker struct {
	C.Conn `json:"-"`
	*TrackerInfo
	manager *Manager

	pushToManager bool `json:"-"`
	user          UserKey
	userStats     bool
	userCloseOnce sync.Once
	quotaExceeded stdatomic.Bool
}

// bindUser remembers the authenticated inbound user for the per-user counters.
func (tt *tcpTracker) bindUser(metadata *C.Metadata) {
	if metadata != nil && metadata.InUser != "" {
		tt.user = UserKey{Inbound: metadata.InName, User: metadata.InUser}
		tt.userStats = true
	}
}

func (tt *tcpTracker) pushUserUploaded(size int64) {
	if tt.userStats {
		DefaultUserManager.PushUploaded(tt.user, size)
		if DefaultLimitManager.AddUsage(tt.user, size) {
			tt.quotaExceeded.Store(true)
		}
	}
}

func (tt *tcpTracker) pushUserDownloaded(size int64) {
	if tt.userStats {
		DefaultUserManager.PushDownloaded(tt.user, size)
		if DefaultLimitManager.AddUsage(tt.user, size) {
			tt.quotaExceeded.Store(true)
		}
	}
}

func (tt *tcpTracker) ID() string {
	return tt.UUID.String()
}

func (tt *tcpTracker) Info() *TrackerInfo {
	return tt.TrackerInfo
}

func (tt *tcpTracker) Read(b []byte) (int, error) {
	n, err := tt.Conn.Read(b)
	download := int64(n)
	if tt.pushToManager {
		tt.manager.PushDownloaded(download)
	}
	tt.pushUserDownloaded(download)
	tt.DownloadTotal.Add(download)
	tt.throttle(int(download), false)
	if tt.quotaExceeded.Load() {
		return n, ErrUserQuotaExceeded
	}
	return n, err
}

func (tt *tcpTracker) ReadBuffer(buffer *buf.Buffer) (err error) {
	err = tt.Conn.ReadBuffer(buffer)
	download := int64(buffer.Len())
	if tt.pushToManager {
		tt.manager.PushDownloaded(download)
	}
	tt.pushUserDownloaded(download)
	tt.DownloadTotal.Add(download)
	tt.throttle(int(download), false)
	if tt.quotaExceeded.Load() {
		return ErrUserQuotaExceeded
	}
	return
}

func (tt *tcpTracker) UnwrapReader() (io.Reader, []N.CountFunc) {
	return tt.Conn, []N.CountFunc{func(download int64) {
		if tt.pushToManager {
			tt.manager.PushDownloaded(download)
		}
		tt.pushUserDownloaded(download)
		tt.DownloadTotal.Add(download)
		tt.throttle(int(download), false)
		if tt.quotaExceeded.Load() {
			_ = tt.Close()
		}
	}}
}

func (tt *tcpTracker) Write(b []byte) (int, error) {
	n, err := tt.Conn.Write(b)
	upload := int64(n)
	if tt.pushToManager {
		tt.manager.PushUploaded(upload)
	}
	tt.pushUserUploaded(upload)
	tt.UploadTotal.Add(upload)
	tt.throttle(int(upload), true)
	if tt.quotaExceeded.Load() {
		return n, ErrUserQuotaExceeded
	}
	return n, err
}

func (tt *tcpTracker) WriteBuffer(buffer *buf.Buffer) (err error) {
	upload := int64(buffer.Len())
	err = tt.Conn.WriteBuffer(buffer)
	if tt.pushToManager {
		tt.manager.PushUploaded(upload)
	}
	tt.pushUserUploaded(upload)
	tt.UploadTotal.Add(upload)
	tt.throttle(int(upload), true)
	if tt.quotaExceeded.Load() {
		return ErrUserQuotaExceeded
	}
	return
}

func (tt *tcpTracker) throttle(n int, upload bool) {
	if !tt.userStats {
		return
	}
	if DefaultLimitManager.Expired(tt.user) {
		_ = tt.Close()
		return
	}
	if n <= 0 {
		return
	}
	if upload {
		DefaultLimitManager.WaitUpload(tt.user, n)
	} else {
		DefaultLimitManager.WaitDownload(tt.user, n)
	}
}

func (tt *tcpTracker) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return tt.Conn, []N.CountFunc{func(upload int64) {
		if tt.pushToManager {
			tt.manager.PushUploaded(upload)
		}
		tt.pushUserUploaded(upload)
		tt.UploadTotal.Add(upload)
		tt.throttle(int(upload), true)
		if tt.quotaExceeded.Load() {
			_ = tt.Close()
		}
	}}
}

func (tt *tcpTracker) Close() error {
	tt.manager.Leave(tt)
	tt.userCloseOnce.Do(func() {
		if tt.userStats {
			DefaultUserManager.Close(tt.user)
			DefaultLimitManager.Disconnect(tt.user)
		}
	})
	return tt.Conn.Close()
}

func (tt *tcpTracker) Upstream() any {
	return tt.Conn
}

func NewTCPTracker(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *tcpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	t := &tcpTracker{
		Conn:    conn,
		manager: manager,
		TrackerInfo: &TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
	}

	if pushToManager {
		if uploadTotal > 0 {
			manager.PushUploaded(uploadTotal)
		}
		if downloadTotal > 0 {
			manager.PushDownloaded(downloadTotal)
		}
	}

	if rule != nil {
		t.TrackerInfo.Rule = rule.RuleType().String()
		t.TrackerInfo.RulePayload = rule.Payload()
	}

	if pushToManager {
		// DNS and dialer-proxy trackers are internal: their connections are not
		// sessions of the inbound user.
		t.bindUser(metadata)
		if t.userStats {
			t.pushUserUploaded(uploadTotal)
			t.pushUserDownloaded(downloadTotal)
			DefaultUserManager.Open(t.user)
			DefaultLimitManager.Connect(t.user)
		}
	}

	manager.Join(t)
	return t
}

type udpTracker struct {
	C.PacketConn `json:"-"`
	*TrackerInfo
	manager *Manager

	pushToManager bool `json:"-"`
	user          UserKey
	userStats     bool
	userCloseOnce sync.Once
	quotaExceeded stdatomic.Bool
}

func (ut *udpTracker) bindUser(metadata *C.Metadata) {
	if metadata != nil && metadata.InUser != "" {
		ut.user = UserKey{Inbound: metadata.InName, User: metadata.InUser}
		ut.userStats = true
	}
}

func (ut *udpTracker) pushUserUploaded(size int64) {
	if ut.userStats {
		DefaultUserManager.PushUploaded(ut.user, size)
		if DefaultLimitManager.AddUsage(ut.user, size) {
			ut.quotaExceeded.Store(true)
		}
	}
}

func (ut *udpTracker) pushUserDownloaded(size int64) {
	if ut.userStats {
		DefaultUserManager.PushDownloaded(ut.user, size)
		if DefaultLimitManager.AddUsage(ut.user, size) {
			ut.quotaExceeded.Store(true)
		}
	}
}

func (ut *udpTracker) throttle(n int, upload bool) {
	if !ut.userStats {
		return
	}
	if DefaultLimitManager.Expired(ut.user) {
		_ = ut.Close()
		return
	}
	if n <= 0 {
		return
	}
	if upload {
		DefaultLimitManager.WaitUpload(ut.user, n)
	} else {
		DefaultLimitManager.WaitDownload(ut.user, n)
	}
}

func (ut *udpTracker) ID() string {
	return ut.UUID.String()
}

func (ut *udpTracker) Info() *TrackerInfo {
	return ut.TrackerInfo
}

func (ut *udpTracker) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := ut.PacketConn.ReadFrom(b)
	download := int64(n)
	if ut.pushToManager {
		ut.manager.PushDownloaded(download)
	}
	ut.pushUserDownloaded(download)
	ut.DownloadTotal.Add(download)
	ut.throttle(int(download), false)
	if ut.quotaExceeded.Load() {
		return 0, addr, ErrUserQuotaExceeded
	}
	return n, addr, err
}

func (ut *udpTracker) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, addr, err = ut.PacketConn.WaitReadFrom()
	download := int64(len(data))
	if ut.pushToManager {
		ut.manager.PushDownloaded(download)
	}
	ut.pushUserDownloaded(download)
	ut.DownloadTotal.Add(download)
	ut.throttle(len(data), false)
	if ut.quotaExceeded.Load() {
		return nil, put, addr, ErrUserQuotaExceeded
	}
	return
}

func (ut *udpTracker) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := ut.PacketConn.WriteTo(b, addr)
	upload := int64(n)
	if ut.pushToManager {
		ut.manager.PushUploaded(upload)
	}
	ut.pushUserUploaded(upload)
	ut.UploadTotal.Add(upload)
	ut.throttle(int(upload), true)
	if ut.quotaExceeded.Load() {
		return n, ErrUserQuotaExceeded
	}
	return n, err
}

func (ut *udpTracker) Close() error {
	ut.manager.Leave(ut)
	ut.userCloseOnce.Do(func() {
		if ut.userStats {
			DefaultUserManager.Close(ut.user)
			DefaultLimitManager.Disconnect(ut.user)
		}
	})
	return ut.PacketConn.Close()
}

func (ut *udpTracker) Upstream() any {
	return ut.PacketConn
}

func NewUDPTracker(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *udpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	ut := &udpTracker{
		PacketConn: conn,
		manager:    manager,
		TrackerInfo: &TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
	}

	if pushToManager {
		if uploadTotal > 0 {
			manager.PushUploaded(uploadTotal)
		}
		if downloadTotal > 0 {
			manager.PushDownloaded(downloadTotal)
		}
	}

	if rule != nil {
		ut.TrackerInfo.Rule = rule.RuleType().String()
		ut.TrackerInfo.RulePayload = rule.Payload()
	}

	if pushToManager {
		ut.bindUser(metadata)
		if ut.userStats {
			ut.pushUserUploaded(uploadTotal)
			ut.pushUserDownloaded(downloadTotal)
			DefaultUserManager.Open(ut.user)
			DefaultLimitManager.Connect(ut.user)
		}
	}

	manager.Join(ut)
	return ut
}
