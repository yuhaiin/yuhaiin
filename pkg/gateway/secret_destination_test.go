package gateway

import (
	"context"
	"errors"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

func credentialedGateway(backend string, headers map[string][]string) contract.Config {
	return contract.Config{
		Rules:     []contract.Rule{{ID: "r", Action: contract.Action{Type: "reverse_proxy", Upstream: "u", Rewrite: contract.Rewrite{Headers: headers}}}},
		Upstreams: []contract.Upstream{{ID: "u", Backends: []contract.Backend{{URL: backend}}}, {ID: "other", Backends: []contract.Backend{{URL: "https://other.example"}}}},
	}
}

func TestUpstreamDestinationIsBoundToRewriteCredentials(t *testing.T) {
	headers := map[string][]string{"Authorization": {"Bearer hunter2"}}
	old := credentialedGateway("https://real.example", headers)
	moved := credentialedGateway("https://attacker.example", headers)
	unmanaged := secret.WithCapabilities(t.Context(), secret.Capabilities{})
	if err := authorizeUpstreamDestinations(unmanaged, old, moved); !errors.Is(err, secret.ErrManage) {
		t.Fatal("rewrite credential was redirected through its upstream", err)
	}
	trust := credentialedGateway("https://real.example", headers)
	trust.Upstreams[0].TrustPEM = "attacker CA"
	if err := authorizeUpstreamDestinations(unmanaged, old, trust); !errors.Is(err, secret.ErrManage) {
		t.Fatal("rewrite credential lost its upstream trust anchor", err)
	}
	fallback := contract.Config{Gateways: []contract.Gateway{{ID: "g", Default: old.Rules[0].Action}}, Upstreams: moved.Upstreams}
	if err := authorizeUpstreamDestinations(unmanaged, contract.Config{Upstreams: old.Upstreams}, fallback); !errors.Is(err, secret.ErrManage) {
		t.Fatal("gateway default action was not covered", err)
	}
	var audited secret.Change
	managed := secret.WithCapabilities(t.Context(), secret.Capabilities{Manage: true, BeforeChange: func(_ context.Context, c secret.Change) error { audited = c; return nil }})
	if err := authorizeUpstreamDestinations(managed, old, moved); err != nil || !audited.Secrets {
		t.Fatal(err, audited)
	}
}

func TestUpstreamChangesWithoutExposureNeedNoManage(t *testing.T) {
	unmanaged := secret.WithCapabilities(t.Context(), secret.Capabilities{})
	headers := map[string][]string{"Authorization": {"Bearer hunter2"}}
	old := credentialedGateway("https://real.example", headers)
	unrelated := credentialedGateway("https://real.example", headers)
	unrelated.Upstreams[1].Backends[0].URL = "https://moved.example"
	if err := authorizeUpstreamDestinations(unmanaged, old, unrelated); err != nil {
		t.Fatal("an upstream without credentials was protected", err)
	}
	limits := credentialedGateway("https://real.example", headers)
	limits.Upstreams[0].MaxConnections = 8
	if err := authorizeUpstreamDestinations(unmanaged, old, limits); err != nil {
		t.Fatal("an unrelated upstream setting was protected", err)
	}
	if err := authorizeUpstreamDestinations(unmanaged, credentialedGateway("https://real.example", nil), credentialedGateway("https://moved.example", nil)); err != nil {
		t.Fatal("a rule without credentials was protected", err)
	}
}
