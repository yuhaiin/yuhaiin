package secret

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type repeatedLayer struct {
	Type     string
	Password string `secret:"true"`
}
type layeredConfig struct {
	ID     string
	Layers []repeatedLayer
}

func TestOpaqueReferencesPreserveRepeatedProtocolLayersOnReorder(t *testing.T) {
	old := layeredConfig{ID: "node", Layers: []repeatedLayer{{Type: "same", Password: "first-private-proof"}, {Type: "same", Password: "second-private-proof"}}}
	next, err := Redact(old)
	if err != nil {
		t.Fatal(err)
	}
	next.Layers[0], next.Layers[1] = next.Layers[1], next.Layers[0]
	if _, err := Merge(WithCapabilities(t.Context(), Capabilities{}), next, old); !errors.Is(err, ErrManage) {
		t.Fatal("reordering protected fields did not require secret management", err)
	}
	merged, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true}), next, old)
	if err != nil || merged.Layers[0].Password != "second-private-proof" || merged.Layers[1].Password != "first-private-proof" {
		t.Fatal("reordered layers acquired the wrong password", err)
	}
}

func TestPreservedReferencesRejectForgeryAndStalePrivateRevisions(t *testing.T) {
	old := layeredConfig{ID: "node", Layers: []repeatedLayer{{Type: "same", Password: "private-proof"}}}
	next, err := Redact(old)
	if err != nil {
		t.Fatal(err)
	}
	text := next.Layers[0].Password
	payload, _, ok := strings.CutLast(strings.TrimPrefix(text, Preserved+"."), ".")
	if !ok {
		t.Fatal("reference is not bound")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || strings.Contains(string(decoded), "private-proof") {
		t.Fatal("reference exposes private configuration", err)
	}
	for _, replacement := range []string{text + "A", strings.Replace(text, "node", "different", 1) + "A"} {
		forged := next
		forged.Layers = append([]repeatedLayer(nil), next.Layers...)
		forged.Layers[0].Password = replacement
		if _, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true}), forged, old); !errors.Is(err, ErrPreserved) {
			t.Fatal("forged preservation capability accepted", err)
		}
	}
	changed := layeredConfig{ID: "node", Layers: []repeatedLayer{{Type: "same", Password: "new-private-proof"}}}
	if _, err := Merge(WithCapabilities(t.Context(), Capabilities{Manage: true}), next, changed); !errors.Is(err, ErrPreserved) {
		t.Fatal("stale draft overwrote a newer credential", err)
	}
}
