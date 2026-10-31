package statistics

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
	"uuid"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

const usagePendingAuditLimit = 8192

// UsageOptions bounds retained on-disk history, independently of configuration
// and credential lifetimes. Runtime observations never contain reusable secrets.
type UsageOptions = usage.Options

func DefaultUsageOptions() UsageOptions {
	return UsageOptions{AuditDays: 30, MaxAuditRows: 100000, HourlyDays: 30, DailyDays: 365}
}

// EnableUserUsage is called once during startup, before any listener accepts
// traffic. Core-only/Android runtimes leave it disabled and keep their current
// transfer path and background-worker count.
func (c *Connections) EnableUserUsage(options UsageOptions) (*UserUsage, error) {
	if c.userUsage != nil {
		return c.userUsage, nil
	}
	r, err := NewUserUsage(c.sqliteDB, options)
	if err == nil {
		c.userUsage = r
	}
	return r, err
}

func trafficIdentityContext(ctx context.Context) context.Context {
	if authorization := netapi.TrafficAuthorizationContext(ctx); authorization != nil {
		return authorization
	}
	if identity := netapi.TrafficIdentity(ctx); identity != nil {
		return identity.Context
	}
	return nil
}

type usageKey struct{ user, credential, inbound, node, protocol string }
type usageBucket struct {
	usageKey
	hour int64
}
type usageActivity struct {
	user   string
	minute int64
}
type usageAmounts struct {
	upload, download, opened, failed, millis uint64
	first, last                              int64
	inboundName, nodeName                    string
}
type usageLive struct {
	tcp, udp, peakTCP, peakUDP int
	upload, download           uint64
}
type usageReader interface {
	LoadUpload() uint64
	LoadDownload() uint64
}

// UserUsage samples the monitor's existing per-connection atomics. Ordinary
// network reads/writes do not call this recorder, acquire its mutex, allocate,
// read a clock, or execute SQL. Only lifecycle events and the background worker
// touch its maps. SQLite I/O always happens after releasing mu.
type UserUsage struct {
	db              *sql.DB
	mu              sync.Mutex
	flushMu         sync.Mutex
	sessions        map[*usageSession]struct{}
	live            map[string]*usageLive
	pending         *usageBatch
	retry           *usageBatch
	boot            string
	sequence        uint64
	options         UsageOptions
	lastSample      time.Time
	lastFlush       int64
	dropped         uint64
	persistError    bool
	lastMaintenance time.Time
	wake            chan struct{}
	stop            chan struct{}
	done            chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

type usageBatch struct {
	id       string
	groups   map[usageBucket]usageAmounts
	activity map[usageActivity]struct{}
	audit    map[string]usage.Audit
	peaks    map[string][2]int
}

type usageSession struct {
	owner            *UserUsage
	reader           usageReader
	key              usageKey
	audit            usage.Audit
	started          time.Time
	identity         context.Context
	up, down, millis uint64
	ended            bool
}

func newUsageBatch() *usageBatch {
	return &usageBatch{groups: make(map[usageBucket]usageAmounts), activity: make(map[usageActivity]struct{}), audit: make(map[string]usage.Audit), peaks: make(map[string][2]int)}
}

// NewUserUsage is initialized before accepting traffic. An interrupted session
// ends at its last persisted checkpoint rather than spanning a process outage.
func NewUserUsage(db *sql.DB, options UsageOptions) (*UserUsage, error) {
	if db == nil {
		return nil, errors.New("user usage requires SQLite")
	}
	var saved string
	if err := db.QueryRowContext(context.Background(), `SELECT options_json FROM user_usage_settings WHERE id=1`).Scan(&saved); err == nil {
		if err := json.Unmarshal([]byte(saved), &options); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err := validateUsageOptions(options); err != nil {
		return nil, err
	}
	r := &UserUsage{db: db, sessions: make(map[*usageSession]struct{}), live: make(map[string]*usageLive), pending: newUsageBatch(), boot: uuid.New().String(), options: options, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), lastSample: time.Now()}
	if err := r.recoverSessions(context.Background()); err != nil {
		return nil, err
	}
	go r.run()
	return r, nil
}

func validateUsageOptions(o UsageOptions) error {
	if o.AuditDays < 1 || o.AuditDays > 365 || o.MaxAuditRows < 100 || o.MaxAuditRows > 1000000 || o.HourlyDays < 1 || o.HourlyDays > 90 || o.DailyDays < o.HourlyDays || o.DailyDays > 730 {
		return errors.New("invalid user usage retention")
	}
	return nil
}

func auditForConnection(info contractconnection.Connection) usage.Audit {
	var decision = info.AccessDecision
	if decision != nil {
		decision = new(*decision)
	}
	return usage.Audit{AccessDecision: decision, UserID: info.UserID, CredentialID: info.CredentialID, GroupIDs: slices.Clone(info.GroupIDs), InboundID: info.InboundID, InboundName: info.InboundName,
		NodeID: info.NodeID, NodeName: info.NodeName, SelectorID: info.SelectorID, SelectorName: info.SelectorName, RuleID: info.RuleID, RuleName: info.RuleName,
		Protocol: info.Network.ConnType, Mode: info.Mode, Source: info.Source, Target: info.Addr, IP: info.IP,
		Upload: "0", Download: "0", DurationMillis: "0", Result: "active"}
}

func (r *UserUsage) register(info contractconnection.Connection, reader usageReader, identity context.Context) *usageSession {
	if r == nil || (info.InboundID == "" && info.Source == "") {
		return nil
	}
	now := time.Now()
	s := &usageSession{owner: r, reader: reader, key: usageKey{info.UserID, info.CredentialID, info.InboundID, info.NodeID, info.Network.ConnType}, audit: auditForConnection(info), started: now, identity: identity}
	r.mu.Lock()
	r.sequence++
	s.audit.ID = r.boot + ":" + strconv.FormatUint(r.sequence, 10)
	s.audit.StartedAt = now.UnixMilli()
	r.sessions[s] = struct{}{}
	live := r.userLocked(s.key.user)
	if s.key.protocol == "udp" {
		live.udp++
		live.peakUDP = max(live.peakUDP, live.udp)
	} else {
		live.tcp++
		live.peakTCP = max(live.peakTCP, live.tcp)
	}
	r.pending.peaks[s.key.user] = [2]int{live.peakTCP, live.peakUDP}
	r.addLocked(s, usageAmounts{opened: 1, first: now.UnixMilli()}, now)
	r.mu.Unlock()
	r.signal()
	return s
}

func (r *UserUsage) userLocked(id string) *usageLive {
	l := r.live[id]
	if l == nil {
		l = new(usageLive)
		r.live[id] = l
	}
	return l
}

func (r *UserUsage) addLocked(s *usageSession, a usageAmounts, at time.Time) {
	k := usageBucket{s.key, at.Unix() / 3600 * 3600}
	a.inboundName, a.nodeName = s.audit.InboundName, s.audit.NodeName
	r.pending.groups[k] = addUsage(r.pending.groups[k], a)
}

func addUsage(a, b usageAmounts) usageAmounts {
	a.upload += b.upload
	a.download += b.download
	a.opened += b.opened
	a.failed += b.failed
	a.millis += b.millis
	if a.first == 0 || (b.first != 0 && b.first < a.first) {
		a.first = b.first
	}
	a.last = max(a.last, b.last)
	if b.inboundName != "" {
		a.inboundName = b.inboundName
	}
	if b.nodeName != "" {
		a.nodeName = b.nodeName
	}
	return a
}

func (s *usageSession) end() {
	if s == nil {
		return
	}
	r := s.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	now := time.Now()
	s.audit.EndedAt = now.UnixMilli()
	if s.audit.Result == "active" {
		s.audit.Result, s.audit.Reason = "closed", "closed"
	}
	if s.audit.Result == "failed" || s.audit.Result == "rejected" {
		r.addLocked(s, usageAmounts{failed: 1}, now)
	}
	if s.identity != nil && s.identity.Err() != nil && !errors.Is(context.Cause(s.identity), netapi.ErrTrafficSessionClosed) {
		s.audit.Reason = "credential_invalidated"
		if errors.Is(context.Cause(s.identity), netapi.ErrTrafficAccessDenied) {
			s.audit.Reason = "access_policy_revoked"
		}
		if errors.Is(context.Cause(s.identity), quota.ErrExhausted) {
			s.audit.Reason = "quota_exhausted"
		}
	}
	live := r.userLocked(s.key.user)
	if s.key.protocol == "udp" {
		live.udp--
	} else {
		live.tcp--
	}
	// Retain the counter until the next sample so a read unblocked by Close can
	// publish its final bytes before the audit checkpoint is serialized.
}

func recordUsageIOError(counter counter, err error) {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}
	if c, ok := counter.(*Counter); ok && c.usage != nil {
		c.usage.fail(err)
	}
}

func (s *usageSession) fail(err error) {
	if s == nil || err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}
	r := s.owner
	r.mu.Lock()
	defer r.mu.Unlock()
	if !s.ended {
		s.audit.Result, s.audit.Reason = usageFailureReason(err)
	}
}

func usageFailureReason(err error) (string, string) {
	if errors.Is(err, quota.ErrExhausted) {
		return "rejected", "quota_exhausted"
	}
	if errors.Is(err, proxyauth.ErrUnauthorized) {
		return "rejected", "authentication_failed"
	}
	if errors.Is(err, netapi.ErrTrafficAccessDenied) {
		return "rejected", "access_policy_denied"
	}
	if netapi.IsBlockError(err) {
		return "rejected", "rule_rejected"
	}
	if errors.Is(err, context.Canceled) {
		return "failed", "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "failed", "timeout"
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return "failed", "timeout"
	}
	return "failed", "connect_error"
}

// Failed proofs have no trusted user identity and stay unattributed.
func (r *UserUsage) AuthenticationFailure(inboundID, protocol string) {
	r.failure(contractconnection.Connection{InboundID: inboundID, Network: contractconnection.NetworkType{ConnType: protocol}}, proxyauth.ErrUnauthorized)
}

func (r *UserUsage) failure(info contractconnection.Connection, err error) {
	result, reason := usageFailureReason(err)
	r.event(info, result, reason)
}

func (r *UserUsage) event(info contractconnection.Connection, result, reason string) {
	if r == nil || (info.InboundID == "" && info.Source == "") {
		return
	}
	now := time.Now()
	s := &usageSession{key: usageKey{info.UserID, info.CredentialID, info.InboundID, info.NodeID, info.Network.ConnType}, audit: auditForConnection(info)}
	s.audit.StartedAt, s.audit.EndedAt = now.UnixMilli(), now.UnixMilli()
	s.audit.Result, s.audit.Reason = result, reason
	r.mu.Lock()
	r.sequence++
	s.audit.ID = r.boot + ":" + strconv.FormatUint(r.sequence, 10)
	a := usageAmounts{first: now.UnixMilli()}
	if result == "failed" || result == "rejected" {
		a.failed = 1
	}
	r.addLocked(s, a, now)
	r.auditLocked(s.audit)
	r.mu.Unlock()
	r.signal()
}

func (r *UserUsage) auditLocked(a usage.Audit) {
	if _, exists := r.pending.audit[a.ID]; !exists && len(r.pending.audit) >= usagePendingAuditLimit {
		r.dropped++
		return
	}
	r.pending.audit[a.ID] = a
}

func (r *UserUsage) sample(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Before(r.lastSample) {
		now = r.lastSample
	}
	elapsed := now.Sub(r.lastSample).Seconds()
	for _, l := range r.live {
		l.upload, l.download = 0, 0
	}
	for s := range r.sessions {
		up, down := s.reader.LoadUpload(), s.reader.LoadDownload()
		u, d := up-s.up, down-s.down
		end := now
		if s.ended {
			end = time.UnixMilli(s.audit.EndedAt)
		}
		millis := max(uint64(max(end.Sub(s.started).Milliseconds(), 0)), s.millis)
		a := usageAmounts{upload: u, download: d, millis: millis - s.millis}
		if u != 0 || d != 0 {
			a.last = end.UnixMilli()
			s.audit.LastSeen = a.last
			r.pending.activity[usageActivity{s.key.user, end.Unix() / 60 * 60}] = struct{}{}
		}
		if u != 0 || d != 0 || a.millis != 0 {
			r.addLocked(s, a, end)
		}
		s.up, s.down, s.millis = up, down, millis
		s.audit.Upload, s.audit.Download, s.audit.DurationMillis = formatUint64(up), formatUint64(down), formatUint64(millis)
		l := r.userLocked(s.key.user)
		l.upload += u
		l.download += d
		r.auditLocked(s.audit)
		if s.ended {
			delete(r.sessions, s)
		}
	}
	if elapsed > 0 {
		for _, l := range r.live {
			l.upload = uint64(float64(l.upload) / elapsed)
			l.download = uint64(float64(l.download) / elapsed)
		}
	}
	r.lastSample = now
}

func (r *UserUsage) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *UserUsage) run() {
	defer close(r.done)
	var timer *time.Timer
	var tick <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	lastFlush := time.Now()
	for {
		select {
		case <-r.stop:
			return
		case <-r.wake:
			if tick == nil {
				if timer == nil {
					timer = time.NewTimer(time.Second)
				} else {
					timer.Reset(time.Second)
				}
				tick = timer.C
			}
		case now := <-tick:
			r.sample(now)
			if now.Sub(lastFlush) >= 5*time.Second {
				if err := r.Flush(context.Background()); err != nil {
					log.Warn("persist user usage failed", "err", err)
				}
				lastFlush = now
			}
			r.mu.Lock()
			busy := len(r.sessions) != 0 || len(r.pending.groups) != 0 || len(r.pending.audit) != 0 || r.persistError
			r.mu.Unlock()
			if busy {
				timer.Reset(time.Second)
			} else {
				tick = nil
			}
		}
	}
}

func (r *UserUsage) healthLocked() usage.Health {
	pending := len(r.pending.audit)
	return usage.Health{PendingAudit: pending, DroppedAudit: formatUint64(r.dropped), LastFlush: r.lastFlush, PersistenceError: r.persistError}
}

func (r *UserUsage) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		close(r.stop)
		<-r.done
		r.mu.Lock()
		for s := range r.sessions {
			if !s.ended {
				s.ended = true
				s.audit.EndedAt = time.Now().UnixMilli()
				s.audit.Result, s.audit.Reason = "closed", "shutdown"
			}
		}
		r.mu.Unlock()
		r.sample(time.Now())
		r.closeErr = r.Flush(context.Background())
	})
	return r.closeErr
}
