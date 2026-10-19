package store

import (
	"errors"
	"testing"

	gateway "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	route "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func TestRouteGatewayTargetValidationAndDeletionProtection(t *testing.T) {
	editor, _, rules := editorStore(t)
	gateways := NewGatewayStore(editor.db)
	config, err := gateways.Save(t.Context(), gateway.Config{Gateways: []gateway.Gateway{{ID: "g", Name: "Gateway", Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	draft := privateDraft("gateway-rule", "Spotify to Gateway")
	draft.Rule.Mode = "gateway"
	draft.Rule.Target = route.Target{Type: "gateway", ID: "missing"}
	if _, err := editor.Save(t.Context(), draft); err == nil {
		t.Fatal("missing Gateway accepted")
	}
	draft.Rule.Target.ID = "g"
	saved, err := editor.Save(t.Context(), draft)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Rule.Target.ID != "g" {
		t.Fatal("Gateway selection was lost")
	}
	remove := config
	remove.Gateways = nil
	_, err = gateways.Save(t.Context(), remove)
	if _, ok := errors.AsType[*ResourceInUseError](err); !ok {
		t.Fatalf("deleted referenced Gateway: %v", err)
	}
	// A saved rule can be removed while its applied snapshot still refers to g.
	snapshot, err := rules.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.ActivateSnapshot(t.Context(), snapshot.Revision, func() {}); err != nil {
		t.Fatal(err)
	}
	if err := rules.DeleteRule(t.Context(), saved.Rule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := gateways.Save(t.Context(), remove); err == nil {
		t.Fatal("deleted Gateway still referenced by running rules")
	}
	snapshot, err = rules.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.ActivateSnapshot(t.Context(), snapshot.Revision, func() {}); err != nil {
		t.Fatal(err)
	}
	if _, err := gateways.Save(t.Context(), remove); err != nil {
		t.Fatal(err)
	}
}
func TestGatewayCannotBeGlobalRoutingDefault(t *testing.T) {
	editor, _, _ := editorStore(t)
	gateways := NewGatewayStore(editor.db)
	if _, err := gateways.Save(t.Context(), gateway.Config{Gateways: []gateway.Gateway{{ID: "g", Name: "Gateway"}}}); err != nil {
		t.Fatal(err)
	}
	settings := NewRouteSettingsStore(editor.db)
	if _, err := settings.SaveConfig(t.Context(), route.Config{DefaultMode: "gateway", DefaultTarget: route.Target{Type: "gateway", ID: "g"}}); err == nil {
		t.Fatal("Gateway accepted as global routing default")
	}
}
