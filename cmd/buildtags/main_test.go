package main

import (
	"slices"
	"testing"

	"tailscale.com/feature/featuretags"
)

// A ts_omit_dns release silently starts tsnet with a nil DNS manager;
// querying 100.100.100.100:53 then panics instead of resolving MagicDNS.
func TestBuildTagsRetainTailscaleDNS(t *testing.T) {
	if _, ok := featuretags.Features["dns"]; !ok {
		t.Fatal("upstream DNS feature is missing from the feature tag registry")
	}
	for _, name := range []string{"dns", "netstack", "serve", "acme", "ipnbus", "udptransport", "nattraversal"} {
		if slices.Contains(buildTags(), "ts_omit_"+name) {
			t.Errorf("required tsnet feature %q omitted from release build", name)
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
