package inbound

import (
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"testing"
)

func TestTunConfigCarriesPerInboundDarwinBatchSettings(t *testing.T) {
	first := tunConfig(contract.TunProtocol{Darwin: contract.DarwinTunOptions{ExperimentalBatch: true, BatchSize: 64, PendingPackets: 128}})
	second := tunConfig(contract.TunProtocol{})
	d := first.Platform.Darwin
	if !d.ExperimentalBatch || d.BatchSize != 64 || d.PendingPackets != 128 {
		t.Fatal("lost Darwin options", d)
	}
	if second.Platform.Darwin.ExperimentalBatch || second.Platform.Darwin.BatchSize != 0 {
		t.Fatal("settings leaked between TUNs")
	}
}
