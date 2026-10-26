package main

import (
	"fmt"
	"slices"
	"strings"

	"tailscale.com/feature/featuretags"
)

// requiredTailscaleFeatures are used by the embedded tsnet adapter. In
// particular, MagicDNS needs the DNS manager even though tsnet can start
// successfully when DNS is omitted.
func requiredTailscaleFeature(name string) bool {
	switch name {
	case "dns", "netstack", "serve", "acme", "ipnbus", "udptransport", "nattraversal":
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
