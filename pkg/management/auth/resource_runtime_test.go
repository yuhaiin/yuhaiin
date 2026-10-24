package auth

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func TestQuotaTerminationInterruptsExistingTCPWithoutRevokingCredential(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	alice, bob := testUser(t, s, "alice", NoManagement), testUser(t, s, "bob", NoManagement)
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	access := accesscontrol.New()
	defer access.Close()
	r, err := NewResourcePolicies(t.Context(), s, p, access)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	issue := func(user User) IssuedProxyCredential {
		t.Helper()
		credential, err := p.Issue(t.Context(), principal(user), ProxyCredentialRequest{Name: "phone"})
		if err != nil {
			t.Fatal(err)
		}
		return credential
	}
	ac, bc := issue(alice), issue(bob)
	config := resource.Config{Enabled: true, DefaultUser: resource.Policy{Quotas: []resource.Quota{{ID: "daily", Period: "daily", Combined: "100", Action: "terminate"}}}}
	if _, err := r.Save(t.Context(), principal(admin), config); err != nil {
		t.Fatal(err)
	}
	verify := p.Verifier("entry", "http", []string{alice.ID, bob.ID})
	aid, err := verify(t.Context(), alice.Login, []byte(ac.Secret))
	if err != nil {
		t.Fatal(err)
	}
	bid, err := verify(t.Context(), bob.Login, []byte(bc.Secret))
	if err != nil {
		t.Fatal(err)
	}
	bind := func(identity *proxyauth.Identity) (net.Conn, net.Conn) {
		t.Helper()
		a, b := net.Pipe()
		ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), identity))
		ctx.SetInboundID("entry")
		target := netapi.ParseIPAddr("tcp", net.IPv4(203, 0, 113, 10), 443)
		conn, err := netapi.BindTrafficConn(ctx, access, target, target, a)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(); _ = b.Close() })
		return conn, b
	}
	first, _ := bind(aid)
	other, peer := bind(bid)
	interrupted := make(chan error, 1)
	go func() { var b [1]byte; _, err := first.Read(b[:]); interrupted <- err }()
	policy := r.Control.ResolveIdentity("entry", "", alice.ID, ac.ID)
	if n, err := (trafficcontrol.ShapedWriter{Writer: io.Discard, Context: t.Context(), Policy: policy, Direction: trafficcontrol.Upload}).Write(make([]byte, 100)); n != 100 || err != nil {
		t.Fatalf("consume quota: %d %v", n, err)
	}
	select {
	case err := <-interrupted:
		if err == nil {
			t.Fatal("quota left TCP usable")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("quota did not promptly interrupt an idle stream")
	}
	if !aid.Valid() {
		t.Fatal("quota invalidated a reusable proxy credential")
	}
	writeDone := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("ok")); writeDone <- err }()
	if err := other.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2)
	if _, err := io.ReadFull(other, data); err != nil || string(data) != "ok" {
		t.Fatalf("unrelated user interrupted: %q %v", data, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if lease, ok := r.Control.AcquireResourceSession(alice.ID, ac.ID, false); ok {
		lease.Release()
		t.Fatal("exhausted user opened another session")
	}
}

func TestResourceReportOwnershipAndAlertCursorPrecision(t *testing.T) {
	s := testStore(t)
	alice, bob := testUser(t, s, "alice", NoManagement), testUser(t, s, "bob", NoManagement)
	r, _ := resourceService(t, s)
	for i, id := range []int64{9007199254740993, 9007199254740994} {
		if _, err := s.db.ExecContext(t.Context(), `INSERT INTO quota_alerts(id,owner_user_id,scope,scope_id,quota_id,period,starts_at,occurred_at,threshold) VALUES(?,?,'user',?,?,'daily',0,1,80)`, id, alice.ID, alice.ID, []string{"one", "two"}[i]); err != nil {
			t.Fatal(err)
		}
	}
	first, err := r.Alerts(t.Context(), alice.ID, "", 1)
	if err != nil || len(first.Items) != 1 || first.Next != "9007199254740994" {
		t.Fatalf("first cursor: %+v %v", first, err)
	}
	second, err := r.Alerts(t.Context(), alice.ID, first.Next, 1)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "9007199254740993" {
		t.Fatalf("rounded cursor: %+v %v", second, err)
	}
	foreign, err := r.Alerts(t.Context(), bob.ID, "", 50)
	if err != nil || len(foreign.Items) != 0 {
		t.Fatal("alerts crossed owner boundary", err)
	}
	server := &Server{Resources: r, Store: s}
	mux := http.NewServeMux()
	server.Register(mux)
	request := httptest.NewRequest("GET", "/api/v2/auth/usage/resources?owner="+bob.ID, nil)
	request = request.WithContext(WithPrincipal(request.Context(), principal(alice)))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), bob.ID) {
		t.Fatalf("foreign resource report: %d", response.Code)
	}
	if server.Permissions["GET /api/v2/auth/usage/resources"] != UsageOwn || server.Permissions["PUT /api/v2/auth/resources"] != ResourceWrite {
		t.Fatal("resource routes lack server permission gates")
	}
}

func TestResourceObserverFailureKeepsUnchangedUsersAuthenticated(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	alice, bob := testUser(t, s, "alice", NoManagement), testUser(t, s, "bob", NoManagement)
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ac, err := p.Issue(t.Context(), principal(alice), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	bc, err := p.Issue(t.Context(), principal(bob), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	verify := p.Verifier("entry", "http", []string{alice.ID, bob.ID})
	previous, err := verify(t.Context(), alice.Login, []byte(ac.Secret))
	if err != nil {
		t.Fatal(err)
	}
	stable, err := verify(t.Context(), bob.Login, []byte(bc.Secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetResourceObserver(func(bindings []trafficcontrol.IdentityBinding) error {
		for _, binding := range bindings {
			if binding.UserID == alice.ID && len(binding.GroupIDs) > 0 {
				return errors.New("resource persistence unavailable")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveGroup(t.Context(), principal(admin), "", GroupRequest{Name: "new limits", Members: []string{alice.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err == nil {
		t.Fatal("failed resource preparation published new authentication")
	}
	if previous.Valid() {
		t.Fatal("changed membership retained old authorization")
	}
	if _, err := verify(t.Context(), alice.Login, []byte(ac.Secret)); err == nil {
		t.Fatal("changed membership escaped resource preparation")
	}
	identity, err := verify(t.Context(), bob.Login, []byte(bc.Secret))
	if err != nil || identity != stable || !stable.Valid() {
		t.Fatal("unrelated identity invalidated", err)
	}
	if err := p.SetResourceObserver(nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t.Context(), alice.Login, []byte(ac.Secret)); err != nil {
		t.Fatal("authentication did not recover", err)
	}
}
