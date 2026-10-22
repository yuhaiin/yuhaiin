package node

import (
	"context"
	"errors"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/credential"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
)

type testCredentials struct {
	revision int64
	missing  bool
}

func (r *testCredentials) Lookup(context.Context, string) (credential.Value, int64, error) {
	if r.missing {
		return credential.Value{}, 0, errors.New("secret unavailable")
	}
	return credential.Value{Type: credential.UsernamePassword, Username: "remote", Password: "secret"}, r.revision, nil
}
func TestReferencedCredentialRefreshesCachedProxyAndFailsClosed(t *testing.T) {
	runtime := newTestRuntime(t)
	resolver := &testCredentials{revision: 1}
	runtime.SetCredentialResolver(resolver)
	node := contractnode.Node{ID: "credential-node", Name: "credential-node", Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "http", CredentialRef: "ref", HTTP: &contractnode.HTTP{}}}}
	if _, err := runtime.Save(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.GetDialerByID(t.Context(), node.ID); err != nil {
		t.Fatal(err)
	}
	before, ok := runtime.proxies.store.Load(node.ID)
	if !ok {
		t.Fatal("missing proxy")
	}
	if before.ContractConfig.Chain[0].HTTP.Password != "" {
		t.Fatal("cache exposed resolved secret as config")
	}
	resolver.revision++
	if _, err := runtime.GetDialerByID(t.Context(), node.ID); err != nil {
		t.Fatal(err)
	}
	after, _ := runtime.proxies.store.Load(node.ID)
	if before == after {
		t.Fatal("credential revision reused stale proxy")
	}
	runtime.InvalidateCredential("ref")
	if _, ok := runtime.proxies.store.Load(node.ID); ok {
		t.Fatal("credential change retained proxy")
	}
	if _, err := runtime.GetDialerByID(t.Context(), node.ID); err != nil {
		t.Fatal(err)
	}
	resolver.missing = true
	if _, err := runtime.GetDialerByID(t.Context(), node.ID); err == nil {
		t.Fatal("missing reference fell back")
	}
	if _, ok := runtime.proxies.store.Load(node.ID); ok {
		t.Fatal("missing reference retained stale cache")
	}
}
