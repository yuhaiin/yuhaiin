package statistics

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/dnshistory"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// DNS history bounds. A record is at most a few kilobytes, so the queue and
// the per-record limits bound memory regardless of the request rate.
const (
	DNSHistoryMaxRetentionHours = 24 * 30
	DNSHistoryMinMaxRecords     = 100
	DNSHistoryMaxMaxRecords     = 200_000
	dnsHistoryRecordsPerSection = 32
	dnsHistoryMaxRDATA          = 512
	dnsHistoryMaxSummary        = 160
	dnsHistoryDefaultPageSize   = 50
	dnsHistoryMaxPageSize       = 200
	dnsHistoryMaxFilterLength   = 253
)

func DefaultDNSHistorySettings() contract.Settings {
	maxRecords := 20_000
	if configuration.Lite {
		maxRecords = 5_000
	}
	return contract.Settings{Enabled: true, RetentionHours: 72, MaxRecords: maxRecords}
}

type DNSHistoryOptions struct {
	QueueSize     int
	BatchSize     int
	FlushInterval time.Duration
	PruneInterval time.Duration
	// writeGate, when set by tests, blocks each batch write until it yields.
	writeGate <-chan struct{}
}

func DefaultDNSHistoryOptions() DNSHistoryOptions {
	if configuration.Lite {
		return DNSHistoryOptions{QueueSize: 512, BatchSize: 64, FlushInterval: 2 * time.Second, PruneInterval: 10 * time.Minute}
	}
	return DNSHistoryOptions{QueueSize: 4096, BatchSize: 256, FlushInterval: time.Second, PruneInterval: 5 * time.Minute}
}

// DNSHistory records DNS requests off the DNS path. BeginDNS returns nil while
// disabled. Completed traces enter a bounded queue without blocking; a full
// queue discards the history record only, and SQLite errors never reach DNS.
type DNSHistory struct {
	db       *sql.DB
	insert   *sql.Stmt
	options  DNSHistoryOptions
	settings atomic.Pointer[contract.Settings]
	enabled  atomic.Bool
	queue    chan *netapi.DNSTraceData
	prune    chan struct{}
	stop     chan struct{}
	done     chan struct{}
	closing  atomic.Bool
	close    sync.Once
	started  time.Time

	persisted     atomic.Uint64
	dropped       atomic.Uint64
	persistErrors atomic.Uint64
	lastError     atomic.Pointer[string]
	settingsMu    sync.Mutex
}

var _ netapi.DNSObserver = (*DNSHistory)(nil)

func NewDNSHistory(db *sql.DB, options DNSHistoryOptions) (*DNSHistory, error) {
	if db == nil {
		return nil, errors.New("dns history requires sqlite")
	}
	defaults := DefaultDNSHistoryOptions()
	if options.QueueSize <= 0 {
		options.QueueSize = defaults.QueueSize
	}
	if options.BatchSize <= 0 {
		options.BatchSize = defaults.BatchSize
	}
	if options.FlushInterval <= 0 {
		options.FlushInterval = defaults.FlushInterval
	}
	if options.PruneInterval <= 0 {
		options.PruneInterval = defaults.PruneInterval
	}
	insert, err := db.PrepareContext(context.Background(), insertDNSHistorySQL)
	if err != nil {
		return nil, fmt.Errorf("prepare dns history insert: %w", err)
	}
	h := &DNSHistory{
		db: db, insert: insert, options: options, started: time.Now(),
		queue: make(chan *netapi.DNSTraceData, options.QueueSize),
		prune: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
	settings, err := h.loadSettings(context.Background())
	if err != nil {
		log.Warn("load dns history settings failed, using defaults", "err", err)
		settings = DefaultDNSHistorySettings()
	}
	h.settings.Store(&settings)
	h.enabled.Store(settings.Enabled)
	go h.run()
	h.requestPrune()
	return h, nil
}

// EnableDNSHistory shares the statistics database, like user usage.
func (c *Connections) EnableDNSHistory(options DNSHistoryOptions) (*DNSHistory, error) {
	if c.dnsHistory != nil {
		return c.dnsHistory, nil
	}
	h, err := NewDNSHistory(c.sqliteDB, options)
	if err == nil {
		c.dnsHistory = h
	}
	return h, err
}

func (h *DNSHistory) BeginDNS(transport, sourceType string) *netapi.DNSTrace {
	if h == nil || !h.enabled.Load() {
		return nil
	}
	return netapi.NewDNSTrace(transport, sourceType, h.enqueue)
}

// enqueue runs on the DNS path when a request completes. It never blocks.
func (h *DNSHistory) enqueue(d *netapi.DNSTraceData) {
	metrics.Counter.AddDNSQueryOutcome(d.Outcome)
	if h.closing.Load() {
		h.dropRecord()
		return
	}
	select {
	case h.queue <- d:
	default:
		h.dropRecord()
	}
}

func (h *DNSHistory) dropRecord() {
	h.dropped.Add(1)
	metrics.Counter.AddDNSHistoryRecordDropped()
}

func (h *DNSHistory) requestPrune() {
	select {
	case h.prune <- struct{}{}:
	default:
	}
}

func (h *DNSHistory) run() {
	defer close(h.done)
	batch := make([]*netapi.DNSTraceData, 0, h.options.BatchSize)
	pruneTicker := time.NewTicker(h.options.PruneInterval)
	defer pruneTicker.Stop()
	timer := time.NewTimer(h.options.FlushInterval)
	timer.Stop()
	for {
		select {
		case <-h.stop:
			h.drain(batch)
			return
		case <-h.prune:
			h.pruneNow()
		case <-pruneTicker.C:
			h.pruneNow()
		case d := <-h.queue:
			batch = append(batch, d)
			timer.Reset(h.options.FlushInterval)
		collect:
			for len(batch) < h.options.BatchSize {
				select {
				case d := <-h.queue:
					batch = append(batch, d)
				case <-timer.C:
					break collect
				case <-h.stop:
					timer.Stop()
					h.drain(batch)
					return
				}
			}
			timer.Stop()
			h.flush(batch)
			clear(batch)
			batch = batch[:0]
		}
	}
}

// drain persists everything already queued when the recorder closes.
func (h *DNSHistory) drain(batch []*netapi.DNSTraceData) {
	for {
		select {
		case d := <-h.queue:
			batch = append(batch, d)
			if len(batch) >= h.options.BatchSize {
				h.flush(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				h.flush(batch)
			}
			return
		}
	}
}

func (h *DNSHistory) flush(batch []*netapi.DNSTraceData) {
	if len(batch) == 0 {
		return
	}
	started := time.Now()
	err := h.write(batch)
	metrics.Counter.ObserveDNSHistoryFlush(time.Since(started))
	metrics.Counter.SetDNSHistoryQueueSize(len(h.queue))
	if err != nil {
		// Records are not retried: memory stays bounded while SQLite fails.
		h.persistErrors.Add(uint64(len(batch)))
		metrics.Counter.AddDNSHistoryPersistenceErrors(len(batch))
		message := err.Error()
		h.lastError.Store(&message)
		log.Warn("persist dns history failed", "records", len(batch), "err", err)
		return
	}
	h.persisted.Add(uint64(len(batch)))
	metrics.Counter.AddDNSHistoryRecords(len(batch))
}

func (h *DNSHistory) write(batch []*netapi.DNSTraceData) error {
	if h.options.writeGate != nil {
		<-h.options.writeGate
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt := tx.StmtContext(ctx, h.insert)
	for _, d := range batch {
		if _, err := stmt.ExecContext(ctx, dnsHistoryRow(d)...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (h *DNSHistory) pruneNow() {
	settings := h.Settings()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cutoff := time.Now().Add(-time.Duration(settings.RetentionHours) * time.Hour).UnixNano()
	if _, err := h.db.ExecContext(ctx, `DELETE FROM dns_query_history WHERE created_at < ?`, cutoff); err != nil {
		log.Warn("prune dns history by age failed", "err", err)
		return
	}
	// The boundary row is found through the (created_at, id) index.
	if _, err := h.db.ExecContext(ctx, `DELETE FROM dns_query_history WHERE id IN (
		SELECT id FROM dns_query_history ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?)`, settings.MaxRecords); err != nil {
		log.Warn("prune dns history by count failed", "err", err)
	}
}

// Close stops recording, persists queued records and waits for the worker.
func (h *DNSHistory) Close() error {
	if h == nil {
		return nil
	}
	h.close.Do(func() {
		h.enabled.Store(false)
		h.closing.Store(true)
		close(h.stop)
		<-h.done
		_ = h.insert.Close()
	})
	return nil
}

func (h *DNSHistory) Settings() contract.Settings {
	if s := h.settings.Load(); s != nil {
		return *s
	}
	return DefaultDNSHistorySettings()
}

func ValidateDNSHistorySettings(s contract.Settings) error {
	if s.RetentionHours < 1 || s.RetentionHours > DNSHistoryMaxRetentionHours {
		return fmt.Errorf("retentionHours must be between 1 and %d", DNSHistoryMaxRetentionHours)
	}
	if s.MaxRecords < DNSHistoryMinMaxRecords || s.MaxRecords > DNSHistoryMaxMaxRecords {
		return fmt.Errorf("maxRecords must be between %d and %d", DNSHistoryMinMaxRecords, DNSHistoryMaxMaxRecords)
	}
	return nil
}

func (h *DNSHistory) SaveSettings(ctx context.Context, s contract.Settings) (contract.Settings, error) {
	if err := ValidateDNSHistorySettings(s); err != nil {
		return contract.Settings{}, err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return contract.Settings{}, err
	}
	h.settingsMu.Lock()
	defer h.settingsMu.Unlock()
	if _, err := h.db.ExecContext(ctx, `INSERT INTO dns_query_history_settings(id, data_json) VALUES(1, ?)
		ON CONFLICT(id) DO UPDATE SET data_json = excluded.data_json`, string(data)); err != nil {
		return contract.Settings{}, err
	}
	h.settings.Store(&s)
	h.enabled.Store(s.Enabled && !h.closing.Load())
	h.requestPrune()
	return s, nil
}

func (h *DNSHistory) loadSettings(ctx context.Context) (contract.Settings, error) {
	var raw string
	err := h.db.QueryRowContext(ctx, `SELECT data_json FROM dns_query_history_settings WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultDNSHistorySettings(), nil
	}
	if err != nil {
		return contract.Settings{}, err
	}
	var s contract.Settings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return contract.Settings{}, err
	}
	if err := ValidateDNSHistorySettings(s); err != nil {
		return contract.Settings{}, err
	}
	return s, nil
}

func (h *DNSHistory) Clear(ctx context.Context) (contract.ClearResponse, error) {
	result, err := h.db.ExecContext(ctx, `DELETE FROM dns_query_history`)
	if err != nil {
		return contract.ClearResponse{}, err
	}
	n, _ := result.RowsAffected()
	return contract.ClearResponse{Deleted: int(n)}, nil
}

func (h *DNSHistory) Status() contract.RecorderStatus {
	status := contract.RecorderStatus{
		Enabled: h.enabled.Load(), QueueLength: len(h.queue), QueueCapacity: cap(h.queue),
		Persisted: h.persisted.Load(), RecordsDropped: h.dropped.Load(), PersistenceErrors: h.persistErrors.Load(),
		StartedAt: h.started.UTC().Format(time.RFC3339Nano),
	}
	if last := h.lastError.Load(); last != nil {
		status.LastPersistenceError = *last
	}
	return status
}

const insertDNSHistorySQL = `INSERT INTO dns_query_history(
	created_at, duration_ns, transport, source_type, source_addr, source_port,
	inbound_id, inbound_name, process_name, pid, uid, user_id, credential_id,
	domain, domain_rev, qtype, qclass, transaction_id,
	resolver, resolver_label, server, server_type, route_mode, route_rule_id, route_rule_name,
	cache_status, resolution_source,
	fakeip_requested, fakeip_returned, fakeip_ipv4, fakeip_ipv6, fakeip_reason,
	outcome, rcode, failure_stage, failure_reason, error,
	request_size, response_size, sent_bytes, answer_count, authority_count, additional_count, answer_summary,
	answer_json, authority_json, additional_json, response_flags_json, details_json
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// NormalizeDNSHistoryDomain is the stored form: lower case, no root dot.
func NormalizeDNSHistoryDomain(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// reverseDomain maps "a.example.com" to "com.example.a." so that a domain and
// its subdomains share the prefix "com.example.".
func reverseDomain(domain string) string {
	if domain == "" {
		return ""
	}
	labels := strings.Split(domain, ".")
	var b strings.Builder
	b.Grow(len(domain) + 1)
	for _, label := range slices.Backward(labels) {
		b.WriteString(label)
		b.WriteByte('.')
	}
	return b.String()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func dnsHistoryRow(d *netapi.DNSTraceData) []any {
	domain := NormalizeDNSHistoryDomain(d.Domain)
	rcode := -1
	var answer, authority, additional []contract.ResourceRecord
	flags := contract.ResponseFlags{ServerTruncated: d.ServerTruncate}
	var counts [3]int
	if r := d.Response; r != nil {
		rcode = int(r.Rcode)
		answer, flags.AnswerOmitted = formatDNSRecords(r.Answer)
		authority, flags.AuthorityOmitted = formatDNSRecords(r.Authority)
		additional, flags.AdditionalOmitted = formatDNSRecords(r.Additional)
		counts = [3]int{len(r.Answer), len(r.Authority), len(r.Additional)}
		flags.AA, flags.TC, flags.RD, flags.RA, flags.AD, flags.CD = r.Authoritative, r.Truncated, r.RecursionDesired, r.RecursionAvailable, r.AuthenticatedData, r.CheckingDisabled
	}
	details := contract.Details{
		Admission: d.Admission, QueueWaitNs: int64(d.QueueWait), SelectionReason: d.SelectionReason,
		ServerTransport: d.ServerTransport, CacheStale: d.CacheStale, SharedQuery: d.SharedQuery, HostsRewrite: NormalizeDNSHistoryDomain(d.HostsRewrite),
		RequestRD: d.RequestRD, RequestCD: d.RequestCD, RequestAD: d.RequestAD, RequestDO: d.RequestDO, RequestUDPSize: int(d.RequestUDPSize),
	}
	for _, a := range d.Attempts {
		details.Attempts = append(details.Attempts, contract.Attempt{Resolver: a.Resolver, Server: a.Server, Transport: a.Transport, OffsetNs: int64(a.Offset), DurationNs: int64(a.Duration), Result: a.Result, Rcode: a.Rcode, Error: a.Error})
	}
	extra := storedDNSDetails{Details: details, GroupIDs: d.GroupIDs, FakeIPPoolIPv4: d.FakeIPPoolIPv4, FakeIPPoolIPv6: d.FakeIPPoolIPv6,
		FakeIPAllocation: d.FakeIPAllocation, FakeIPError: d.FakeIPError, FakeIPForce: d.ForceFakeIP, FakeIPGlobal: d.FakeIPGlobal, FakeIPSkipCheck: d.FakeIPSkipCheck}
	return []any{
		d.CreatedAt.UnixNano(), int64(d.Duration), d.Transport, d.SourceType, d.ClientIP, int(d.ClientPort),
		d.InboundID, d.InboundName, d.ProcessName, int64(d.PID), int64(d.UID), d.UserID, d.CredentialID,
		domain, reverseDomain(domain), int(d.QType), int(d.QClass), int(d.TransactionID),
		d.Resolver, d.ResolverLabel, d.Server, d.ServerType, d.RouteMode, d.RouteRuleID, d.RouteRuleName,
		d.CacheStatus, d.Source,
		boolInt(d.FakeIPRequested), boolInt(d.FakeIPReturned), d.FakeIPv4, d.FakeIPv6, d.FakeIPReason,
		d.Outcome, rcode, d.FailureStage, d.FailureReason, d.Error,
		d.RequestSize, d.ResponseSize, d.SentBytes, counts[0], counts[1], counts[2], answerSummary(answer),
		mustJSON(answer, "[]"), mustJSON(authority, "[]"), mustJSON(additional, "[]"), mustJSON(flags, "{}"), mustJSON(extra, "{}"),
	}
}

// storedDNSDetails is details_json: display-only fields nobody filters on.
type storedDNSDetails struct {
	contract.Details
	GroupIDs         []string `json:"groupIds,omitempty"`
	FakeIPPoolIPv4   string   `json:"fakeipPoolIpv4,omitempty"`
	FakeIPPoolIPv6   string   `json:"fakeipPoolIpv6,omitempty"`
	FakeIPAllocation string   `json:"fakeipAllocation,omitempty"`
	FakeIPError      string   `json:"fakeipError,omitempty"`
	FakeIPForce      bool     `json:"fakeipForce,omitempty"`
	FakeIPGlobal     bool     `json:"fakeipGlobal,omitempty"`
	FakeIPSkipCheck  bool     `json:"fakeipSkipCheck,omitempty"`
}

func mustJSON(v any, empty string) string {
	data, err := json.Marshal(v)
	if err != nil || string(data) == "null" {
		return empty
	}
	return string(data)
}

// formatDNSRecords renders every RR type generically in presentation format.
// The section is capped; the number of omitted records is returned.
func formatDNSRecords(rrs []dns.RR) ([]contract.ResourceRecord, int) {
	if len(rrs) == 0 {
		return nil, 0
	}
	n := min(len(rrs), dnsHistoryRecordsPerSection)
	out := make([]contract.ResourceRecord, 0, n)
	for _, rr := range rrs[:n] {
		if rr == nil {
			continue
		}
		h := rr.Header()
		record := contract.ResourceRecord{
			Name: NormalizeDNSHistoryDomain(h.Name), Type: dnsutil.TypeToString(dns.RRToType(rr)),
			Class: dnsutil.ClassToString(h.Class), TTL: h.TTL,
		}
		if data := rr.Data(); data != nil {
			record.Data = data.String()
		}
		if len(record.Data) > dnsHistoryMaxRDATA {
			record.Data, record.DataTruncated = record.Data[:dnsHistoryMaxRDATA], true
		}
		out = append(out, record)
	}
	return out, len(rrs) - n
}

func answerSummary(records []contract.ResourceRecord) string {
	var b strings.Builder
	for _, r := range records {
		if r.Data == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(r.Data)
		if b.Len() >= dnsHistoryMaxSummary {
			break
		}
	}
	s := b.String()
	if len(s) > dnsHistoryMaxSummary {
		cut := dnsHistoryMaxSummary
		for cut > 0 && s[cut]&0xC0 == 0x80 {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}
