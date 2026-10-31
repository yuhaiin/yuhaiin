package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	accesscontract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestAccessPolicyGuardsLocalGatewayResponsesOnReusedIdentity(t *testing.T) {
	access := accesscontrol.New()
	defer access.Close()
	engine, err := NewEngine(contract.Gateway{ID: "web", Default: contract.Action{Type: "respond", Status: 200, Body: "private"}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.access = access
	prepare := func(action string) {
		t.Helper()
		p, err := accesscontrol.Prepare(accesscontract.Config{Enabled: true, Scope: accesscontract.Scope{AllInbounds: true}, DefaultAction: action})
		if err != nil {
			t.Fatal(err)
		}
		access.Activate(p)
	}
	prepare("allow")
	ctx := netapi.WithContext(t.Context())
	ctx.SetInboundID("gateway:web")
	serve := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://192.0.2.8/private", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}
	if w := serve(); w.Code != 403 || w.Body.String() == "private" {
		t.Fatal("anonymous local Gateway bypass", w.Code)
	}
	ctx = netapi.WithContext(netapi.WithTrafficIdentity(ctx, &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}))
	ctx.SetInboundID("entry")
	if w := serve(); w.Code != 200 || w.Body.String() != "private" {
		t.Fatal("allowed local response", w.Code, w.Body.String())
	}
	prepare("deny")
	if w := serve(); w.Code != 403 {
		t.Fatal("reused authenticated connection bypassed new policy", w.Code)
	}
	if access.Status().Sessions != 0 {
		t.Fatal("local response leaked session")
	}
}

func TestGatewayPoolDoesNotReuseRetiredAuthenticationGeneration(t *testing.T) {
	pool := NewTransportPool(4)
	defer pool.Close()
	address, _ := netapi.ParseAddress("tcp", "192.0.2.8:80")
	first := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}
	selection := Selection{Identity: "direct", Proxy: netapi.NewErrProxy(nil), Destination: address, TrafficScope: "phone", TrafficGeneration: first}
	old, release, err := pool.borrow(selection, "http://service.example", contract.Upstream{})
	if err != nil {
		t.Fatal(err)
	}
	release()
	same, release, err := pool.borrow(selection, "http://service.example", contract.Upstream{})
	if err != nil {
		t.Fatal(err)
	}
	release()
	if same != old {
		t.Fatal("unchanged identity lost keepalive")
	}
	selection.TrafficGeneration = &proxyauth.Identity{UserID: first.UserID, CredentialID: first.CredentialID, Context: t.Context()}
	fresh, release, err := pool.borrow(selection, "http://service.example", contract.Upstream{})
	if err != nil {
		t.Fatal(err)
	}
	release()
	if fresh == old {
		t.Fatal("new credential snapshot retained a dial bound to retired identity")
	}
}

type blockedAccessResponse struct {
	header            http.Header
	writing, deadline chan struct{}
	once              sync.Once
}

func (w *blockedAccessResponse) Header() http.Header { return w.header }
func (*blockedAccessResponse) WriteHeader(int)       {}
func (w *blockedAccessResponse) Write([]byte) (int, error) {
	close(w.writing)
	<-w.deadline
	return 0, context.DeadlineExceeded
}
func (w *blockedAccessResponse) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		w.once.Do(func() { close(w.deadline) })
	}
	return nil
}

func TestAccessRevocationInterruptsBlockedLocalGatewayWrite(t *testing.T) {
	access := accesscontrol.New()
	defer access.Close()
	activate := func(action string) {
		t.Helper()
		p, err := accesscontrol.Prepare(accesscontract.Config{Enabled: true, Scope: accesscontract.Scope{AllInbounds: true}, DefaultAction: action})
		if err != nil {
			t.Fatal(err)
		}
		access.Activate(p)
	}
	activate("allow")
	engine, err := NewEngine(contract.Gateway{ID: "web", Default: contract.Action{Type: "respond", Body: "private"}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.access = access
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}))
	ctx.SetInboundID("entry")
	writer := &blockedAccessResponse{header: make(http.Header), writing: make(chan struct{}), deadline: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		engine.ServeHTTP(writer, httptest.NewRequest("GET", "http://192.0.2.8/private", nil).WithContext(ctx))
	}()
	select {
	case <-writer.writing:
	case <-time.After(time.Second):
		t.Fatal("response did not start")
	}
	activate("deny")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoked local response remained blocked")
	}
	if access.Status().Sessions != 0 {
		t.Fatal("blocked response authorization leaked")
	}
}
