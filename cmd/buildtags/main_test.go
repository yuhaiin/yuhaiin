package main

import (
	"slices"
	"testing"

	"tailscale.com/feature/featuretags"
)

// The lite adapter owns MagicDNS responses and does not use tsnet.
func TestBuildTagsRetainTailscaleDNS(t *testing.T) {
	if _, ok := featuretags.Features["dns"]; !ok {
		t.Fatal("upstream DNS feature is missing from the feature tag registry")
	}
	for _, name := range []string{"dns", "udptransport", "nattraversal"} {
		if slices.Contains(buildTags(), "ts_omit_"+name) {
			t.Errorf("required Tailnet feature %q omitted from release build", name)
		}
	}
	for _, name := range []string{"netstack", "serve", "acme", "ipnbus"} {
		if _, exists := featuretags.Features[featuretags.Feature(name)]; exists && !slices.Contains(buildTags(), "ts_omit_"+name) {
			t.Errorf("unneeded feature %q was linked", name)
		}
	}
}

func TestBuildTagsStableAndUnique(t *testing.T) {
	tags := buildTags()
	if !slices.IsSorted(tags) {
		t.Fatal("feature build tags must be deterministic")
	}
	for i := 1; i < len(tags); i++ {
		if tags[i] == tags[i-1] {
			t.Fatalf("duplicate feature build tag %q", tags[i])
		}
	}
}
