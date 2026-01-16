package domain

import (
	"fmt"
	"math/rand"
	"strings"
)

func randomDomainParts(depth int) string {
	parts := make([]string, depth)
	tlds := []string{"com", "net", "org", "cn", "io"}
	parts[0] = tlds[rand.Intn(len(tlds))]
	for i := 1; i < depth; i++ {
		parts[i] = fmt.Sprintf("sub%d-%d", i, rand.Intn(1000))
	}
	return strings.Join(parts, ".")
}
