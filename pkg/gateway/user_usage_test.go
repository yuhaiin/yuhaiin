package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestGatewayLocalActionsAuditAuthorityWithoutURLOrPayload(t *testing.T) {
	for _, action := range []contract.Action{{Type: "respond", Body: "local"}, {Type: "block"}, {Type: "redirect", Status: 307, Location: "/new"}} {
		t.Run(action.Type, func(t *testing.T) {
			engine, err := NewEngine(contract.Gateway{ID: "g", Default: action}, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			calls := 0
			engine.localAudit = func(_ *netapi.Context, target string, blocked bool) {
				calls++
				if target != "example.com:443" || blocked != (action.Type == "block") {
					t.Fatalf("audit=%q blocked=%t", target, blocked)
				}
			}
			engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://example.com/private?secret=value", nil))
			if calls != 1 {
				t.Fatalf("local audit calls=%d", calls)
			}
		})
	}
}

func TestAuthenticatedGatewayPoolSeparatesTrafficAttribution(t *testing.T) {
	engine, proxy := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	// Production authentication returns one immutable identity until reload.
	identities := map[string]*proxyauth.Identity{}
	request := func(user, credential, inbound string, port int) {
		identity := identities[credential]
		if identity == nil {
			identity = &proxyauth.Identity{UserID: user, CredentialID: credential, Context: t.Context()}
			identities[credential] = identity
		}
		ctx := netapi.WithContext(netapi.WithTrafficIdentity(context.Background(), identity))
		ctx.Source = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: port}
		ctx.SetInboundID(inbound)
		req := httptest.NewRequest("GET", "http://example.com/", nil).WithContext(WithMetadata(ctx, Metadata{Context: ctx}))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("request=%d %s", w.Code, w.Body)
		}
	}
	request("alice", "phone", "entry", 1234)
	request("alice", "phone", "entry", 1234)
	if proxy.dials.Load() != 1 {
		t.Fatal("same traffic scope did not retain keepalive")
	}
	request("bob", "bob-phone", "entry", 1234)
	request("alice", "phone", "other-entry", 1234)
	request("alice", "phone", "entry", 5678)
	if proxy.dials.Load() != 4 {
		t.Fatalf("traffic scopes shared an upstream connection: dials=%d", proxy.dials.Load())
	}
}
