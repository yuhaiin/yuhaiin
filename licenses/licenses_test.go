package licenses

import (
	"testing"
)

func TestRegexp(t *testing.T) {
	t.Log(Yuhaiin())
	t.Log(Android())
}

// The notice is embedded in binary distributions independently of the generated
// dependency list, which does not discover adapted in-repository algorithms.
func TestBBRAttribution(t *testing.T) {
	for _, l := range Yuhaiin() {
		if l.Name == "google/bbr (BBR v3 adaptation)" && l.License == "BSD-3-Clause" {
			return
		}
	}
	t.Fatal("BBR v3 notice missing from distributed licenses")
}
