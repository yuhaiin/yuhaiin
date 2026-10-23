package main

import (
	"fmt"
	"slices"
	"strings"

	"tailscale.com/feature/featuretags"
)

// Retain only features required by the embedded WireGuard/magicsock control
// engine; Tailscale netstack, Serve, ACME and ipnbus are not linked.
func requiredTailscaleFeature(name string) bool {
	switch name {
	case "dns", "udptransport", "nattraversal":
		return true
	default:
		return false
	}
}

func buildTags() []string {
	tags := make([]string, 0, len(featuretags.Features))
	for name := range featuretags.Features {
		if requiredTailscaleFeature(string(name)) {
			continue
		}
		tags = append(tags, "ts_omit_"+string(name))
	}
	slices.Sort(tags)
	return tags
}

func main() {
	fmt.Println(strings.Join(buildTags(), ","))
}
