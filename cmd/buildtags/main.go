package main

import (
	"fmt"
	"strings"

	"tailscale.com/feature/featuretags"
)

func main() {
	tags := make([]string, 0, len(featuretags.Features))

	for k := range featuretags.Features {
		switch k {
		case "netstack", "serve", "acme", "dns":
			continue
		}

		tags = append(tags, "ts_omit_"+string(k))
	}

	fmt.Println(strings.Join(tags, ","))
}
