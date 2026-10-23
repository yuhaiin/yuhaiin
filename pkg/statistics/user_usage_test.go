package statistics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

type usageTestCounter struct{ upload, download atomic.Uint64 }

func (c *usageTestCounter) LoadUpload() uint64   { return c.upload.Load() }
func (c *usageTestCounter) LoadDownload() uint64 { return c.download.Load() }

func usageTestRecorder(t testing.TB) *UserUsage {
	t.Helper()
	s, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewUserUsage(s.DB(), DefaultUsageOptions())
	if err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		_ = s.Close()
	})
	return r
}

func usageInfo(user, credential, node string) contractconnection.Connection {
	return contractconnection.Connection{UserID: user, CredentialID: credential, InboundID: "entry", InboundName: "Entry", NodeID: node, NodeName: "Node " + node, Source: "192.0.2.1:54321", Addr: "example.com:443", Network: contractconnection.NetworkType{ConnType: "tcp"}}
}

func usageReport(t testing.TB, r *UserUsage, user string) usage.Report {
	t.Helper()
	r.sample(time.Now())
	out, err := r.Report(t.Context(), usage.Query{UserID: user})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUserUsageExcludesInfrastructureWithInheritedIdentity(t *testing.T) {
	r := usageTestRecorder(t)
	info := usageInfo("alice", "phone", "dns-upstream")
	info.InboundID, info.Source = "", ""
	if session := r.register(info, new(usageTestCounter), nil); session != nil {
		t.Fatal("internal upstream inherited client accounting")
	}
	r.failure(info, context.DeadlineExceeded)
	if report := usageReport(t, r, "alice"); report.Summary.Lifetime.Opened != "0" || report.Summary.Lifetime.Failed != "0" {
		t.Fatalf("internal activity=%+v", report.Summary)
	}
}

func TestUserUsageSeparatesOwnersCredentialsAndNodes(t *testing.T) {
	r := usageTestRecorder(t)
	for _, tc := range []struct {
		user, credential, node string
		bytes                  uint64
	}{{"alice", "phone", "one", 10}, {"alice", "computer", "two", 20}, {"bob", "phone", "one", 40}, {"", "", "one", 80}} {
		c := new(usageTestCounter)
		s := r.register(usageInfo(tc.user, tc.credential, tc.node), c, nil)
		c.upload.Add(tc.bytes)
		c.download.Add(tc.bytes * 2)
		s.end()
		s.end()
	}
	a := usageReport(t, r, "alice")
	if a.Summary.Lifetime.Upload != "30" || a.Summary.Lifetime.Download != "60" || a.Summary.Lifetime.Opened != "2" || a.Summary.ActiveTCP != 0 || a.Summary.PeakTCP != 1 {
		t.Fatalf("alice=%+v", a.Summary)
	}
	if len(a.Nodes) != 2 || len(a.Credentials) != 2 || a.Summary.ActiveMinutes != "1" {
		t.Fatalf("breakdown=%+v", a)
	}
	for _, tc := range []struct{ user, want string }{{"bob", "40"}, {"", "80"}} {
		if got := usageReport(t, r, tc.user).Summary.Lifetime.Upload; got != tc.want {
			t.Fatalf("%s=%s", tc.user, got)
		}
	}
	page, err := r.Audit(t.Context(), usage.Query{UserID: "alice", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Next == "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	next, err := r.Audit(t.Context(), usage.Query{UserID: "alice", Limit: 1, Before: page.Next})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID == page.Items[0].ID || next.Next != "" {
		t.Fatalf("next=%+v err=%v", next, err)
	}
	for _, row := range append(page.Items, next.Items...) {
		if row.UserID != "alice" || row.Result != "closed" || row.Target != "example.com:443" {
			t.Fatalf("audit=%+v", row)
		}
	}
}

func TestUserUsageRetentionKeepsLifetimeDailyRollupAndActiveAudit(t *testing.T) {
	r := usageTestRecorder(t)
	options := DefaultUsageOptions()
	options.HourlyDays, options.AuditDays, options.MaxAuditRows = 1, 1, 100
	if err := r.SetOptions(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Truncate(24 * time.Hour).Add(-48 * time.Hour)
	s := &usageSession{key: usageKey{user: "alice", credential: "phone", inbound: "entry", node: "one", protocol: "tcp"}, audit: auditForConnection(usageInfo("alice", "phone", "one"))}
	r.mu.Lock()
	r.addLocked(s, usageAmounts{upload: 10, opened: 1, first: old.UnixMilli(), last: old.UnixMilli()}, old)
	r.addLocked(s, usageAmounts{upload: 20, first: old.Add(time.Hour).UnixMilli(), last: old.Add(time.Hour).UnixMilli()}, old.Add(time.Hour))
	r.mu.Unlock()
	if err := r.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.maintainUsage(t.Context(), options, time.Now()); err != nil {
		t.Fatal(err)
	}
	day, err := r.Report(t.Context(), usage.Query{UserID: "alice", Interval: "day", From: old.Unix(), To: old.Add(24 * time.Hour).Unix()})
	if err != nil || day.Summary.Lifetime.Upload != "30" || day.Summary.Period.Upload != "30" || len(day.Series) != 1 || day.Series[0].Opened != "1" {
		t.Fatalf("daily=%+v err=%v", day, err)
	}
	var hours int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM user_usage_buckets WHERE period='hour'`).Scan(&hours); err != nil || hours != 0 {
		t.Fatalf("expired hours=%d err=%v", hours, err)
	}
	for range 110 {
		c := new(usageTestCounter)
		session := r.register(usageInfo("alice", "phone", "one"), c, nil)
		c.download.Add(1)
		session.end()
	}
	active := r.register(usageInfo("alice", "phone", "one"), new(usageTestCounter), nil)
	defer active.end()
	r.sample(time.Now())
	page, err := r.Audit(t.Context(), usage.Query{UserID: "alice", Limit: 200})
	if err != nil || len(page.Items) != 101 {
		t.Fatalf("capped audit rows=%d err=%v", len(page.Items), err)
	}
	ongoing, err := r.Audit(t.Context(), usage.Query{UserID: "alice", Result: "active", Source: "192.0.2.1:54321", Target: "example.com:443"})
	if err != nil || len(ongoing.Items) != 1 {
		t.Fatalf("active audit=%+v err=%v", ongoing, err)
	}
	report := usageReport(t, r, "alice")
	if report.Summary.Lifetime.Download != "110" || report.Summary.Lifetime.Opened != "112" {
		t.Fatalf("cap changed aggregates: %+v", report.Summary)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewUserUsage(r.db, DefaultUsageOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Options() != options {
		t.Fatalf("saved options=%+v", reopened.Options())
	}
}

func TestUserUsageLocalFailureAndGatewayActions(t *testing.T) {
	r := usageTestRecorder(t)
	local := r.Local(usageInfo("alice", "phone", "@local-dns"), nil)
	local.AddUpload(23)
	local.Finish(context.DeadlineExceeded)
	local.Finish(context.DeadlineExceeded)
	c := &Connections{userUsage: r}
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}))
	ctx.Source = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	ctx.SetInboundID("entry")
	c.RecordGatewayAction(ctx, "example.com:80", false)
	c.RecordGatewayAction(ctx, "example.com:443", true)
	report := usageReport(t, r, "alice")
	if report.Summary.Lifetime.Upload != "23" || report.Summary.Lifetime.Failed != "2" || report.Summary.Lifetime.Opened != "1" || report.Summary.ActiveTCP != 0 {
		t.Fatalf("summary=%+v", report.Summary)
	}
	page, err := r.Audit(t.Context(), usage.Query{UserID: "alice", NodeID: "@local-gateway"})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("gateway=%+v err=%v", page, err)
	}
	for _, item := range page.Items {
		if item.Upload != "0" || item.Download != "0" || item.Mode != "gateway" {
			t.Fatalf("local action=%+v", item)
		}
	}
}

type usagePartialConn struct{ usageBenchmarkConn }

func (usagePartialConn) Write(p []byte) (int, error) { return min(3, len(p)), context.DeadlineExceeded }

func TestUserUsagePartialWriteCountsActualBytesAndFailure(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "state.db"), relayConnProxy{conn: usagePartialConn{}})
	defer c.Close()
	r, err := c.EnableUserUsage(DefaultUsageOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}))
	ctx.SetInboundID("entry")
	stream, err := c.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Write([]byte("payload")); n != 3 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write=%d %v", n, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if report := usageReport(t, r, "alice"); report.Summary.Lifetime.Upload != "3" || report.Summary.Lifetime.Failed != "1" {
		t.Fatalf("partial transfer=%+v", report.Summary)
	}
}

func TestUserUsageActivityDeduplicatesConcurrentCredentials(t *testing.T) {
	r := usageTestRecorder(t)
	c1, c2 := new(usageTestCounter), new(usageTestCounter)
	s1 := r.register(usageInfo("alice", "phone", "one"), c1, nil)
	s2 := r.register(usageInfo("alice", "computer", "one"), c2, nil)
	c1.upload.Add(1)
	c2.upload.Add(1)
	first := usageReport(t, r, "alice")
	if first.Summary.ActiveMinutes != "1" || first.Summary.ActiveTCP != 2 || first.Summary.PeakTCP != 2 {
		t.Fatalf("summary=%+v", first.Summary)
	}
	c1.upload.Add(1)
	c2.upload.Add(1)
	if got := usageReport(t, r, "alice").Summary.ActiveMinutes; got != "1" {
		t.Fatalf("minutes=%s", got)
	}
	s1.end()
	s2.end()
}

func TestUserUsageFailedFlushRetainsImmutableBatch(t *testing.T) {
	r := usageTestRecorder(t)
	c := new(usageTestCounter)
	s := r.register(usageInfo("alice", "phone", "one"), c, nil)
	c.upload.Add(10)
	r.sample(time.Now())
	if _, err := r.db.Exec(`CREATE TRIGGER usage_write_failure BEFORE INSERT ON user_usage_totals BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(t.Context()); err == nil || !r.Health().PersistenceError {
		t.Fatal("expected observable write failure")
	}
	c.upload.Add(20)
	s.end()
	r.sample(time.Now())
	if _, err := r.db.Exec(`DROP TRIGGER usage_write_failure`); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := usageReport(t, r, "alice").Summary.Lifetime.Upload; got != "30" {
		t.Fatalf("upload=%s", got)
	}
	if r.Health().PersistenceError {
		t.Fatal("error not cleared")
	}
}

func TestUserUsageCommittedBatchRetryIsIdempotent(t *testing.T) {
	r := usageTestRecorder(t)
	c := new(usageTestCounter)
	s := r.register(usageInfo("alice", "phone", "one"), c, nil)
	c.upload.Add(123)
	s.end()
	r.sample(time.Now())
	r.mu.Lock()
	b := r.pending
	r.pending = newUsageBatch()
	b.id = "ambiguous-commit"
	r.mu.Unlock()
	if err := r.persistUsage(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := r.persistUsage(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if got := usageReport(t, r, "alice").Summary.Lifetime.Upload; got != "123" {
		t.Fatalf("upload=%s", got)
	}
}

func TestUserUsageRestartRetainsHistoryAndMarksInterrupted(t *testing.T) {
	r := usageTestRecorder(t)
	c := new(usageTestCounter)
	s := r.register(usageInfo("alice", "old-token", "deleted-node"), c, nil)
	c.download.Add(123)
	usageReport(t, r, "alice")
	// Simulate recovery while the previous runtime's persisted session is open.
	if err := r.recoverSessions(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, err := r.Audit(t.Context(), usage.Query{UserID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Result != "interrupted" || page.Items[0].EndedAt == 0 {
		t.Fatalf("audit=%+v", page)
	}
	s.end()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := NewUserUsage(r.db, DefaultUsageOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if got := usageReport(t, next, "alice"); got.Summary.Lifetime.Download != "123" || got.Summary.ActiveTCP != 0 || got.Summary.ActiveMinutes != "1" {
		t.Fatalf("restarted=%+v", got)
	}
}

func TestUserUsageAuditOverflowPreservesUsage(t *testing.T) {
	r := usageTestRecorder(t)
	r.mu.Lock()
	for i := range usagePendingAuditLimit {
		r.pending.audit[fmt.Sprint(i)] = usage.Audit{ID: fmt.Sprint(i)}
	}
	r.mu.Unlock()
	c := new(usageTestCounter)
	s := r.register(usageInfo("alice", "phone", "one"), c, nil)
	c.upload.Add(10)
	s.end()
	got := usageReport(t, r, "alice")
	if got.Summary.Lifetime.Upload != "10" || got.Health.DroppedAudit != "1" {
		t.Fatalf("overflow=%+v", got)
	}
}

func TestUserUsageFailuresAndCredentialCancellation(t *testing.T) {
	r := usageTestRecorder(t)
	r.failure(usageInfo("alice", "phone", "one"), &net.OpError{Op: "block", Err: errors.New("rejected")})
	ctx, cancel := context.WithCancel(t.Context())
	c := new(usageTestCounter)
	s := r.register(usageInfo("alice", "phone", "one"), c, ctx)
	cancel()
	s.end()
	got := usageReport(t, r, "alice")
	if got.Summary.Lifetime.Failed != "1" || got.Summary.Lifetime.Opened != "1" {
		t.Fatalf("summary=%+v", got.Summary)
	}
	page, err := r.Audit(t.Context(), usage.Query{UserID: "alice", Result: "rejected"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Reason != "rule_rejected" {
		t.Fatalf("audit=%+v err=%v", page, err)
	}
	page, err = r.Audit(t.Context(), usage.Query{UserID: "alice", Result: "closed"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Reason != "credential_invalidated" {
		t.Fatalf("audit=%+v err=%v", page, err)
	}
}

func TestUserUsageConcurrentTransferSamplingAndClose(t *testing.T) {
	r := usageTestRecorder(t)
	const users, iterations = 8, 1000
	var wg sync.WaitGroup
	for i := range users {
		wg.Go(func() {
			c := new(usageTestCounter)
			s := r.register(usageInfo(fmt.Sprint(i), "phone", "one"), c, nil)
			for range iterations {
				c.upload.Add(1)
				c.download.Add(2)
			}
			s.end()
		})
	}
	wg.Go(func() {
		for range 50 {
			r.sample(time.Now())
		}
	})
	wg.Wait()
	for i := range users {
		got := usageReport(t, r, fmt.Sprint(i))
		if got.Summary.Lifetime.Upload != "1000" || got.Summary.Lifetime.Download != "2000" || got.Summary.ActiveTCP != 0 {
			t.Fatalf("summary=%+v", got.Summary)
		}
	}
}

func TestUserUsageProductionConnectionSamplesExistingCounter(t *testing.T) {
	left, right := pipe.Pipe()
	defer left.Close()
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "state.db"), relayConnProxy{conn: right})
	defer c.Close()
	r, err := c.EnableUserUsage(DefaultUsageOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}))
	ctx.SetInboundID("entry")
	ctx.Hash, ctx.NodeName = "one", "Node one"
	conn, err := c.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := left.Write([]byte("hello")); done <- err }()
	if n, err := conn.Read(make([]byte, 5)); err != nil || n != 5 {
		t.Fatalf("read=%d %v", n, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	got := usageReport(t, r, "alice")
	if got.Summary.Lifetime.Download != "5" || got.Summary.Lifetime.Opened != "1" {
		t.Fatalf("summary=%+v", got.Summary)
	}
}
