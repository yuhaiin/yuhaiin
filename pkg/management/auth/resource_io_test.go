package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func resourceTestManager(t *testing.T, action string) (*trafficcontrol.Manager, resource.Config, []trafficcontrol.IdentityBinding) {
	t.Helper()
	l := quota.New(quotaStore{db: testStore(t).db})
	t.Cleanup(func() {
		if err := l.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	m := trafficcontrol.NewManagerWithQuotas(l)
	c := resource.Config{Enabled: true, DefaultUser: resource.Policy{Quotas: []resource.Quota{{ID: "daily", Period: "daily", Combined: "100", Action: action}}}}
	b := []trafficcontrol.IdentityBinding{{UserID: "alice", CredentialID: "phone"}, {UserID: "alice", CredentialID: "laptop"}, {UserID: "bob", CredentialID: "bob"}}
	if err := m.ApplyResources(c, b); err != nil {
		t.Fatal(err)
	}
	return m, c, b
}

func TestLiveQuotaStreamEnforcementSharesUserAcrossDevices(t *testing.T) {
	m, _, _ := resourceTestManager(t, "terminate")
	var output bytes.Buffer
	phone := m.ResolveIdentity("", "", "alice", "phone")
	write := trafficcontrol.ShapedWriter{Writer: &output, Context: t.Context(), Policy: phone, Direction: trafficcontrol.Upload}
	n, err := write.Write(make([]byte, 70))
	if n != 70 || err != nil {
		t.Fatalf("first device: %d %v", n, err)
	}
	laptop := m.ResolveIdentity("", "", "alice", "laptop")
	write.Policy = laptop
	n, err = write.Write(make([]byte, 50))
	if n != 30 || !errors.Is(err, quota.ErrExhausted) || output.Len() != 100 {
		t.Fatalf("live shared quota bypass: %d %v output=%d", n, err, output.Len())
	}
	plan, err := phone.QuotaPlan()
	if err != nil || plan.Usage()[0].Used.Combined != "100" {
		t.Fatalf("incorrect edge accounting: %v", err)
	}
	write.Policy = m.ResolveIdentity("", "", "bob", "bob")
	if n, err := write.Write(make([]byte, 100)); n != 100 || err != nil {
		t.Fatalf("unrelated user blocked: %d %v", n, err)
	}
}

func TestQuotaBackpressurePreservesDeadlineAndPolicyUpdates(t *testing.T) {
	m, config, bindings := resourceTestManager(t, "block_new")
	a, b := net.Pipe()
	defer b.Close()
	conn := trafficcontrol.WrapConn(t.Context(), a, func() trafficcontrol.Policy { return m.ResolveIdentity("", "", "alice", "phone") })
	defer conn.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(io.Discard, b) }()
	if n, err := conn.Write(make([]byte, 100)); n != 100 || err != nil {
		t.Fatalf("initial write: %d %v", n, err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write([]byte{1}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("quota did not backpressure to deadline: %d %v", n, err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := conn.Write([]byte{1}); written <- err }()
	config.DefaultUser.Quotas[0].Combined = "200"
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("policy activation did not wake blocked stream")
	}
	_ = conn.Close()
	<-done
}

type failedQuotaWriter struct{}

func (failedQuotaWriter) Write(p []byte) (int, error) { return min(7, len(p)), io.ErrShortWrite }

func TestQuotaRefundsShortStreamWritesAndDatagrams(t *testing.T) {
	m, _, _ := resourceTestManager(t, "terminate")
	p := m.ResolveIdentity("", "", "alice", "phone")
	n, err := (trafficcontrol.ShapedWriter{Writer: failedQuotaWriter{}, Context: t.Context(), Policy: p, Direction: trafficcontrol.Download}).Write(make([]byte, 50))
	if n != 7 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer: %d %v", n, err)
	}
	plan, _ := p.QuotaPlan()
	if plan.Usage()[0].Used.Combined != "7" {
		t.Fatal("unwritten stream bytes were charged")
	}
	var ticket quota.Reservation
	until := time.Now().Add(5 * time.Second)
	// The first UDP attempt may request a direction's first durable grant.
	for {
		metered, err := p.ReserveDatagram(trafficcontrol.Upload, 40, &ticket)
		if errors.Is(err, quota.ErrFunding) {
			if time.Now().After(until) {
				t.Fatal("durable UDP credit was not published")
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil || !metered {
			t.Fatalf("datagram reservation: %v", err)
		}
		break
	}
	ticket.Commit(0)
	if plan.Usage()[0].Used.Combined != "7" {
		t.Fatal("failed datagram consumed quota")
	}
}

func TestGroupQuotaThrottleSharesReducedBudgetAcrossMembers(t *testing.T) {
	m, config, bindings := resourceTestManager(t, "terminate")
	config.DefaultUser.Quotas = nil
	config.Groups = []resource.GroupPolicy{{GroupID: "finance", Quotas: []resource.Quota{{ID: "group-daily", Period: "daily", Combined: "100", Action: "throttle", ReducedSpeed: resource.Profile{Upload: resource.Rate{BytesPerSecond: 1, BurstBytes: 2}}}}}}
	for i := range bindings {
		bindings[i].GroupIDs = []string{"finance"}
	}
	if err := m.ApplyResources(config, bindings); err != nil {
		t.Fatal(err)
	}
	alice := m.ResolveIdentity("", "", "alice", "phone")
	bob := m.ResolveIdentity("", "", "bob", "bob")
	if n, err := (trafficcontrol.ShapedWriter{Writer: io.Discard, Context: t.Context(), Policy: alice, Direction: trafficcontrol.Upload}).Write(make([]byte, 100)); n != 100 || err != nil {
		t.Fatalf("before quota: %d %v", n, err)
	}
	var ticket quota.Reservation
	if metered, err := alice.ReserveDatagram(trafficcontrol.Upload, 1, &ticket); err != nil || !metered {
		t.Fatalf("first reduced-speed byte: %v", err)
	}
	ticket.Commit(1)
	if _, err := bob.ReserveDatagram(trafficcontrol.Upload, 2, &ticket); !errors.Is(err, trafficcontrol.ErrRateLimited) {
		t.Fatalf("per-member buckets bypassed aggregate throttle: %v", err)
	}
	if _, err := bob.ReserveDatagram(trafficcontrol.Upload, 1, &ticket); err != nil {
		t.Fatalf("rejected packet consumed remaining group burst: %v", err)
	}
	ticket.Commit(1)
	if _, err := alice.ReserveDatagram(trafficcontrol.Upload, 1, &ticket); !errors.Is(err, trafficcontrol.ErrRateLimited) {
		t.Fatalf("shared reduced burst bypassed: %v", err)
	}
	plan, _ := alice.QuotaPlan()
	if usage := plan.Usage()[0]; usage.Used.Combined != "102" {
		t.Fatalf("dropped packets consumed quota: %+v", usage)
	}
}
