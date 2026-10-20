package gateway

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func workspaceFixture() Config {
	return Config{
		Revision: 7,
		Gateways: []Gateway{{
			ID: "site", Name: "Site", Enabled: true, Revision: 3,
			Listen: "127.0.0.1:8080", TLSMode: "off", RuleIDs: []string{"path"},
			Default: Action{Type: "reverse_proxy", Upstream: "pool",
				Outbound: route.Target{Type: "inherit_route"}},
		}},
		Rules: []Rule{{
			ID: "path", Name: "Block ads", Enabled: true, Priority: 10,
			Match:  Condition{Field: "path", Operator: "prefix", Values: []string{"/ads/"}},
			Action: Action{Type: "block", Status: 204},
		}},
		Upstreams: []Upstream{{
			ID: "pool", Name: "Local", Backends: []Backend{{URL: "http://127.0.0.1:3000", Weight: 1}},
			Balance: "round_robin",
		}},
		Interceptions: []Interception{{
			GatewayID: "site", Mode: "http_only",
			Domains: []string{"example.com"}, UnknownTLS: "passthrough",
		}},
		FilterLists: []FilterList{{
			ID: "filter", Name: "Ads", GatewayID: "site", Enabled: true,
			Text: "||example.com/ads/*",
		}},
	}
}

func TestWorkspaceRoundTripPreservesOwnedResources(t *testing.T) {
	original := workspaceFixture()
	document, err := WorkspaceFromConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	if document.Revision != original.Revision || len(document.Gateways) != 1 {
		t.Fatalf("bad document: %+v", document)
	}
	g := document.Gateways[0]
	if g.Listener == nil || g.Listener.Listen != "127.0.0.1:8080" ||
		len(g.Policies) != 1 || len(g.BackendPools) != 1 ||
		g.Interception == nil || len(g.Filters) != 1 {
		t.Fatalf("lost Gateway resources: %+v", g)
	}
	converted, err := ConfigFromWorkspace(document)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, converted) {
		t.Fatalf("projection is not lossless:\noriginal=%+v\nconverted=%+v", original, converted)
	}
}

func TestWorkspaceProjectionRejectsSharingOrOrphans(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"orphan rule", func(c *Config) {
			c.Gateways[0].RuleIDs = nil
		}, "orphan HTTP policy"},
		{"shared rule", func(c *Config) {
			c.Gateways = append(c.Gateways, Gateway{
				ID: "other", Name: "Other", RuleIDs: []string{"path"},
			})
		}, "multiple Gateways"},
		{"missing pool", func(c *Config) {
			c.Upstreams = nil
		}, "missing backend pool"},
		{"orphan pool", func(c *Config) {
			c.Gateways[0].Default = Action{Type: "forward"}
		}, "orphan backend pool"},
		{"orphan Gateway interception", func(c *Config) {
			c.Interceptions[0].GatewayID = "missing"
		}, "orphan Gateway interception"},
		{"orphan filter", func(c *Config) {
			c.FilterLists[0].GatewayID = "missing"
		}, "orphan filters"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := workspaceFixture()
			tt.edit(&c)
			_, err := WorkspaceFromConfig(c)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestWorkspaceRejectsForeignPoolAndDuplicateInterception(t *testing.T) {
	doc, err := WorkspaceFromConfig(workspaceFixture())
	if err != nil {
		t.Fatal(err)
	}
	doc.Gateways[0].BackendPools = nil
	if _, err := ConfigFromWorkspace(doc); err == nil || !strings.Contains(err.Error(), "foreign backend pool") {
		t.Fatalf("foreign backend pool: %v", err)
	}
	config := workspaceFixture()
	config.Interceptions = append(config.Interceptions, config.Interceptions[0])
	if _, err := WorkspaceFromConfig(config); err == nil || !strings.Contains(err.Error(), "duplicate Gateway interception") {
		t.Fatalf("duplicate interception: %v", err)
	}
}

func TestWorkspacePreservesListenerlessInterception(t *testing.T) {
	original := workspaceFixture()
	original.Gateways[0].Listen = ""
	original.Gateways[0].TLSMode = ""
	doc, err := WorkspaceFromConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Gateways[0].Listener != nil {
		t.Fatalf("interception unexpectedly started listener: %+v", doc.Gateways[0].Listener)
	}
	converted, err := ConfigFromWorkspace(doc)
	if err != nil {
		t.Fatal(err)
	}
	if converted.Gateways[0].Listen != "" || len(converted.Interceptions) != 1 {
		t.Fatalf("interception source missing: %+v", converted)
	}
}
