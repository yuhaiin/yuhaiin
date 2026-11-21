package statistics

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns/dnsutil"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/dnshistory"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// ErrDNSHistoryBadRequest wraps invalid filter or cursor input.
var ErrDNSHistoryBadRequest = errors.New("invalid dns history request")

func badDNSHistoryRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDNSHistoryBadRequest, fmt.Sprintf(format, args...))
}

var dnsHistoryOutcomes = map[string]bool{
	netapi.DNSOutcomeSuccess: true, netapi.DNSOutcomeNXDomain: true, netapi.DNSOutcomeNoData: true,
	netapi.DNSOutcomeServFail: true, netapi.DNSOutcomeRefused: true, netapi.DNSOutcomeOtherRcode: true,
	netapi.DNSOutcomeTimeout: true, netapi.DNSOutcomeCanceled: true, netapi.DNSOutcomeRejected: true,
	netapi.DNSOutcomeDropped: true, netapi.DNSOutcomeMalformed: true, netapi.DNSOutcomeWriteError: true,
	netapi.DNSOutcomeInternal: true,
}

// Answered outcomes delivered a DNS answer; everything else counts as failed.
const dnsHistoryAnsweredSQL = `outcome IN ('success','nxdomain','nodata')`

type dnsHistoryWhere struct {
	clauses []string
	args    []any
}

func (w *dnsHistoryWhere) add(clause string, args ...any) {
	w.clauses = append(w.clauses, clause)
	w.args = append(w.args, args...)
}

func (w *dnsHistoryWhere) sql() string {
	if len(w.clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.clauses, " AND ")
}

func checkFilterLength(name, value string) error {
	if len(value) > dnsHistoryMaxFilterLength {
		return badDNSHistoryRequest("%s is too long", name)
	}
	return nil
}

// buildDNSHistoryFilter turns a request into parameterized SQL. User input is
// never concatenated into the statement.
func buildDNSHistoryFilter(r contract.ListRequest) (*dnsHistoryWhere, error) {
	w := &dnsHistoryWhere{}
	for name, value := range map[string]string{"domain": r.Domain, "query": r.Query, "process": r.Process, "resolver": r.Resolver, "server": r.Server, "inboundId": r.InboundID} {
		if err := checkFilterLength(name, value); err != nil {
			return nil, err
		}
	}
	if domain := NormalizeDNSHistoryDomain(strings.TrimPrefix(strings.TrimSpace(r.Domain), "*.")); domain != "" {
		prefix := reverseDomain(domain)
		// Index range on domain_rev: the name itself and every subdomain.
		w.add(`domain_rev >= ? AND domain_rev < ?`, prefix, prefix[:len(prefix)-1]+"/")
	}
	if q := strings.ToLower(strings.TrimSpace(r.Query)); q != "" {
		w.add(`(instr(domain, ?) > 0 OR instr(lower(process_name), ?) > 0 OR instr(source_addr, ?) > 0)`, q, q, q)
	}
	if t := strings.ToUpper(strings.TrimSpace(r.QueryType)); t != "" {
		qtype, err := dnsutil.StringToType(t)
		if err != nil {
			return nil, badDNSHistoryRequest("unknown query type %q", r.QueryType)
		}
		w.add(`qtype = ?`, int(qtype))
	}
	switch r.Transport {
	case "":
	case "udp", "tcp":
		w.add(`transport = ?`, r.Transport)
	default:
		return nil, badDNSHistoryRequest("unknown transport %q", r.Transport)
	}
	switch r.SourceType {
	case "":
	case netapi.DNSSourceLocal, netapi.DNSSourceHijack:
		w.add(`source_type = ?`, r.SourceType)
	default:
		return nil, badDNSHistoryRequest("unknown source type %q", r.SourceType)
	}
	if r.InboundID != "" {
		w.add(`inbound_id = ?`, r.InboundID)
	}
	if p := strings.ToLower(strings.TrimSpace(r.Process)); p != "" {
		w.add(`instr(lower(process_name), ?) > 0`, p)
	}
	if r.Resolver != "" {
		w.add(`(resolver = ? OR resolver_label = ?)`, r.Resolver, r.Resolver)
	}
	if r.Server != "" {
		w.add(`server = ?`, r.Server)
	}
	if r.Outcome != "" {
		values := strings.Split(r.Outcome, ",")
		if len(values) > len(dnsHistoryOutcomes) {
			return nil, badDNSHistoryRequest("too many outcomes")
		}
		placeholders := make([]string, 0, len(values))
		for _, v := range values {
			v = strings.TrimSpace(v)
			if !dnsHistoryOutcomes[v] {
				return nil, badDNSHistoryRequest("unknown outcome %q", v)
			}
			placeholders = append(placeholders, "?")
			w.args = append(w.args, v)
		}
		w.clauses = append(w.clauses, `outcome IN (`+strings.Join(placeholders, ",")+`)`)
	}
	if rc := strings.ToUpper(strings.TrimSpace(r.Rcode)); rc != "" {
		code, err := dnsutil.StringToRcode(rc)
		if err != nil {
			return nil, badDNSHistoryRequest("unknown rcode %q", r.Rcode)
		}
		w.add(`rcode = ?`, int(code))
	}
	if r.FakeIPOnly {
		w.add(`fakeip_returned = 1`)
	}
	if r.From < 0 || r.To < 0 || (r.To != 0 && r.From > r.To) {
		return nil, badDNSHistoryRequest("invalid time range")
	}
	if r.From > 0 {
		w.add(`created_at >= ?`, time.UnixMilli(r.From).UnixNano())
	}
	if r.To > 0 {
		w.add(`created_at < ?`, time.UnixMilli(r.To).UnixNano())
	}
	return w, nil
}

func encodeDNSHistoryCursor(createdAt, id int64) string {
	return strconv.FormatInt(createdAt, 36) + "." + strconv.FormatInt(id, 36)
}

func decodeDNSHistoryCursor(cursor string) (int64, int64, error) {
	a, b, ok := strings.Cut(cursor, ".")
	if !ok || len(cursor) > 64 {
		return 0, 0, badDNSHistoryRequest("invalid cursor")
	}
	createdAt, err1 := strconv.ParseInt(a, 36, 64)
	id, err2 := strconv.ParseInt(b, 36, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, badDNSHistoryRequest("invalid cursor")
	}
	return createdAt, id, nil
}

const dnsHistoryListColumns = `id, created_at, duration_ns, transport, source_type, source_addr, source_port,
	inbound_id, inbound_name, process_name, pid, uid, user_id, credential_id,
	domain, qtype, qclass, transaction_id, resolver, resolver_label, server, server_type,
	route_mode, route_rule_id, route_rule_name, cache_status, resolution_source,
	fakeip_requested, fakeip_returned, fakeip_ipv4, fakeip_ipv6, fakeip_reason,
	outcome, rcode, failure_stage, failure_reason, error,
	request_size, response_size, sent_bytes, answer_count, authority_count, additional_count, answer_summary`

const dnsHistoryDetailColumns = dnsHistoryListColumns + `, answer_json, authority_json, additional_json, response_flags_json, details_json`

// List returns one page in stable (created_at DESC, id DESC) order. The cursor
// is the last row's key, so equal timestamps never repeat or skip rows.
func (h *DNSHistory) List(ctx context.Context, r contract.ListRequest) (contract.ListResponse, error) {
	limit := r.Limit
	if limit <= 0 {
		limit = dnsHistoryDefaultPageSize
	}
	limit = min(limit, dnsHistoryMaxPageSize)
	w, err := buildDNSHistoryFilter(r)
	if err != nil {
		return contract.ListResponse{}, err
	}
	var total int
	if err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_query_history`+w.sql(), w.args...).Scan(&total); err != nil {
		return contract.ListResponse{}, err
	}
	if r.Cursor != "" {
		createdAt, id, err := decodeDNSHistoryCursor(r.Cursor)
		if err != nil {
			return contract.ListResponse{}, err
		}
		w.add(`(created_at < ? OR (created_at = ? AND id < ?))`, createdAt, createdAt, id)
	}
	args := append(w.args, limit+1)
	rows, err := h.db.QueryContext(ctx, `SELECT `+dnsHistoryListColumns+` FROM dns_query_history`+w.sql()+` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return contract.ListResponse{}, err
	}
	defer rows.Close()
	out := contract.ListResponse{Items: make([]contract.Record, 0, limit), Total: total, Limit: limit}
	var lastCreated []int64
	for rows.Next() {
		record, createdAt, err := scanDNSHistory(rows, false)
		if err != nil {
			return contract.ListResponse{}, err
		}
		out.Items = append(out.Items, record)
		lastCreated = append(lastCreated, createdAt)
	}
	if err := rows.Err(); err != nil {
		return contract.ListResponse{}, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1]
		out.NextCursor = encodeDNSHistoryCursor(lastCreated[limit-1], last.ID)
	}
	return out, nil
}

var ErrDNSHistoryNotFound = errors.New("dns history record not found")

func (h *DNSHistory) Get(ctx context.Context, id int64) (contract.Record, error) {
	row := h.db.QueryRowContext(ctx, `SELECT `+dnsHistoryDetailColumns+` FROM dns_query_history WHERE id = ?`, id)
	record, _, err := scanDNSHistory(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.Record{}, ErrDNSHistoryNotFound
	}
	return record, err
}

type dnsHistoryScanner interface{ Scan(...any) error }

func scanDNSHistory(row dnsHistoryScanner, detail bool) (contract.Record, int64, error) {
	var r contract.Record
	var createdAt int64
	var qtype, qclass, rcode int
	var requested, returned int
	dest := []any{&r.ID, &createdAt, &r.DurationNs, &r.Transport, &r.SourceType, &r.ClientIP, &r.ClientPort,
		&r.InboundID, &r.InboundName, &r.ProcessName, &r.PID, &r.UID, &r.UserID, &r.CredentialID,
		&r.Domain, &qtype, &qclass, &r.TransactionID, &r.Resolver, &r.ResolverLabel, &r.Server, &r.ServerType,
		&r.RouteMode, &r.RouteRuleID, &r.RouteRuleName, &r.CacheStatus, &r.ResolutionSource,
		&requested, &returned, &r.FakeIP.IPv4, &r.FakeIP.IPv6, &r.FakeIP.Reason,
		&r.Outcome, &rcode, &r.FailureStage, &r.FailureReason, &r.Error,
		&r.RequestSize, &r.ResponseSize, &r.SentBytes, &r.AnswerCount, &r.AuthorityCount, &r.AdditionalCount, &r.AnswerSummary}
	var answer, authority, additional, flags, details string
	if detail {
		dest = append(dest, &answer, &authority, &additional, &flags, &details)
	}
	if err := row.Scan(dest...); err != nil {
		return r, 0, err
	}
	r.CreatedAt = time.Unix(0, createdAt).UTC().Format(time.RFC3339Nano)
	r.QueryType = dnsutil.TypeToString(uint16(qtype))
	r.QueryClass = dnsutil.ClassToString(uint16(qclass))
	if rcode >= 0 {
		r.Rcode = dnsutil.RcodeToString(uint16(rcode))
	}
	r.FakeIP.Requested, r.FakeIP.Returned = requested == 1, returned == 1
	if !detail {
		return r, createdAt, nil
	}
	var stored storedDNSDetails
	var responseFlags contract.ResponseFlags
	err := errors.Join(
		json.Unmarshal([]byte(answer), &r.Answer),
		json.Unmarshal([]byte(authority), &r.Authority),
		json.Unmarshal([]byte(additional), &r.Additional),
		json.Unmarshal([]byte(flags), &responseFlags),
		json.Unmarshal([]byte(details), &stored),
	)
	if err != nil {
		return r, 0, fmt.Errorf("decode dns history record %d: %w", r.ID, err)
	}
	r.Flags = &responseFlags
	r.Details = &stored.Details
	r.GroupIDs = stored.GroupIDs
	r.FakeIP.PoolIPv4, r.FakeIP.PoolIPv6 = stored.FakeIPPoolIPv4, stored.FakeIPPoolIPv6
	r.FakeIP.Allocation, r.FakeIP.Error = stored.FakeIPAllocation, stored.FakeIPError
	r.FakeIP.Force, r.FakeIP.Global, r.FakeIP.SkipCheck = stored.FakeIPForce, stored.FakeIPGlobal, stored.FakeIPSkipCheck
	return r, createdAt, nil
}

// Stats aggregates one time range in a single indexed pass. Retention bounds
// the table, so the scan is bounded too.
func (h *DNSHistory) Stats(ctx context.Context, r contract.StatsRequest) (contract.Stats, error) {
	now := time.Now()
	to := r.To
	if to <= 0 {
		to = now.UnixMilli() + 1
	}
	from := r.From
	if from <= 0 {
		from = now.Add(-24 * time.Hour).UnixMilli()
	}
	if from > to {
		return contract.Stats{}, badDNSHistoryRequest("invalid time range")
	}
	s := contract.Stats{From: from, To: to, Recorder: h.Status()}
	var avg sql.NullFloat64
	var sums [7]sql.NullInt64
	err := h.db.QueryRowContext(ctx, `SELECT COUNT(*),
		SUM(`+dnsHistoryAnsweredSQL+`), SUM(outcome = 'dropped'), SUM(outcome = 'timeout'), SUM(outcome = 'write_error'),
		SUM(fakeip_returned), SUM(cache_status = 'hit'), SUM(cache_status = 'miss'), AVG(duration_ns)
		FROM dns_query_history WHERE created_at >= ? AND created_at < ?`,
		time.UnixMilli(from).UnixNano(), time.UnixMilli(to).UnixNano(),
	).Scan(&s.Total, &sums[0], &sums[1], &sums[2], &sums[3], &sums[4], &sums[5], &sums[6], &avg)
	if err != nil {
		return contract.Stats{}, err
	}
	s.Success, s.Dropped, s.Timeout, s.WriteErrors = int(sums[0].Int64), int(sums[1].Int64), int(sums[2].Int64), int(sums[3].Int64)
	s.FakeIP, s.CacheHits, s.CacheMisses = int(sums[4].Int64), int(sums[5].Int64), int(sums[6].Int64)
	s.Failed = s.Total - s.Success
	s.AvgLatencyNs = avg.Float64
	return s, nil
}
