package secret_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

func securedNode() node.Node {
	return node.Node{ID: "n", Name: "old", Chain: []node.Protocol{
		{Type: "fixed", Fixed: &node.Fixed{Host: "real.example", Port: 22}},
		{Type: "http", HTTP: &node.HTTP{User: "u", Password: "hunter2"}},
	}}
}

func TestPreservedCredentialCannotChangeDestinationWithoutManage(t *testing.T) {
	old := securedNode()
	masked, err := secret.Redact(old)
	if err != nil {
		t.Fatal(err)
	}
	masked.Chain[0].Fixed.Host = "attacker.example"
	unmanaged := secret.WithCapabilities(t.Context(), secret.Capabilities{})
	if _, err := secret.Merge(unmanaged, masked, old); !errors.Is(err, secret.ErrManage) {
		t.Fatal("credential was redirected without secrets:manage", err)
	}
	var change secret.Change
	managed := secret.WithCapabilities(t.Context(), secret.Capabilities{Manage: true, BeforeChange: func(_ context.Context, c secret.Change) error { change = c; return nil }})
	got, err := secret.Merge(managed, masked, old)
	if err != nil || got.Chain[0].Fixed.Host != "attacker.example" || got.Chain[1].HTTP.Password != "hunter2" {
		t.Fatal(got, err)
	}
	if !change.Secrets {
		t.Fatal("a redirected credential was not audited as a secret change")
	}
}

func TestUnrelatedEditKeepsMaskedCredentialWithoutManage(t *testing.T) {
	old := securedNode()
	masked, err := secret.Redact(old)
	if err != nil {
		t.Fatal(err)
	}
	masked.Name = "renamed"
	got, err := secret.Merge(secret.WithCapabilities(t.Context(), secret.Capabilities{}), masked, old)
	if err != nil || got.Name != "renamed" || got.Chain[1].HTTP.Password != "hunter2" {
		t.Fatal(got, err)
	}
}

func TestDestinationWithoutCredentialNeedsNoManage(t *testing.T) {
	old := node.Node{ID: "n", Chain: []node.Protocol{{Type: "fixed", Fixed: &node.Fixed{Host: "real.example", Port: 22}}}}
	next := node.Node{ID: "n", Chain: []node.Protocol{{Type: "fixed", Fixed: &node.Fixed{Host: "other.example", Port: 22}}}}
	got, err := secret.Merge(secret.WithCapabilities(t.Context(), secret.Capabilities{}), next, old)
	if err != nil || got.Chain[0].Fixed.Host != "other.example" {
		t.Fatal(got, err)
	}
}

func TestPublicationAndGatewayDestinationsAreBound(t *testing.T) {
	unmanaged := secret.WithCapabilities(t.Context(), secret.Capabilities{})
	publish := subscription.Publish{Name: "p", Password: "hunter2", Address: "real.example"}
	maskedPublish, err := secret.Redact(publish)
	if err != nil {
		t.Fatal(err)
	}
	maskedPublish.Address = "attacker.example"
	if _, err := secret.Merge(unmanaged, maskedPublish, publish); !errors.Is(err, secret.ErrManage) {
		t.Fatal("publication credential was redirected", err)
	}
	maskedPublish.Address, maskedPublish.Insecure = publish.Address, true
	if _, err := secret.Merge(unmanaged, maskedPublish, publish); !errors.Is(err, secret.ErrManage) {
		t.Fatal("publication credential lost TLS verification", err)
	}
	headers := gateway.Action{Type: "proxy", Upstream: "real", Rewrite: gateway.Rewrite{Host: "real.example", Headers: map[string][]string{"Authorization": {"Bearer hunter2"}}}}
	maskedAction, err := secret.Redact(headers)
	if err != nil {
		t.Fatal(err)
	}
	maskedAction.Rewrite.Host = "attacker.example"
	if _, err := secret.Merge(unmanaged, maskedAction, headers); !errors.Is(err, secret.ErrManage) {
		t.Fatal("rewrite credential was redirected", err)
	}
	maskedAction.Rewrite.Host = headers.Rewrite.Host
	maskedAction.Upstream = "attacker"
	if _, err := secret.Merge(unmanaged, maskedAction, headers); !errors.Is(err, secret.ErrManage) {
		t.Fatal("action credential was redirected", err)
	}
}
