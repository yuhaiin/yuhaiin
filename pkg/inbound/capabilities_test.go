package inbound

import (
	"slices"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
)

func TestPlatformCapabilities(t *testing.T) {
	for _, test := range []struct {
		os, arch           string
		tun, tproxy, redir bool
	}{
		{"linux", "amd64", true, true, true}, {"android", "arm64", true, true, true},
		{"darwin", "arm64", true, false, true}, {"windows", "amd64", true, false, false},
		{"freebsd", "amd64", true, false, false}, {"freebsd", "ppc64", false, false, false},
		{"plan9", "amd64", false, false, false},
	} {
		t.Run(test.os+"/"+test.arch, func(t *testing.T) {
			caps := capabilitiesFor(test.os, test.arch)
			if caps.Platform != test.os || slices.Contains(caps.Protocols, contract.ProtocolTun) != test.tun || slices.Contains(caps.Protocols, contract.ProtocolTProxy) != test.tproxy || slices.Contains(caps.Protocols, contract.ProtocolRedir) != test.redir {
				t.Fatalf("capabilities: %+v", caps)
			}
		})
	}
}
