package migrate

import (
	"testing"

	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

func TestConvertLegacyNodeUsesChain(t *testing.T) {
	point := (&legacy.Point_builder{
		Hash:   new("n1"),
		Name:   new("direct"),
		Origin: legacy.Origin_manual.Enum(),
		Protocols: []*legacy.Protocol{
			(&legacy.Protocol_builder{Direct: &legacy.Direct{}}).Build(),
		},
	}).Build()

	node, warnings, err := ConvertLegacyNode(point)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", warnings)
	}
	if got := node.Chain[0].Type; got != "direct" {
		t.Fatalf("protocol type = %q", got)
	}

	roundtrip, err := ConvertContractNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if roundtrip.GetProtocols()[0].GetDirect() == nil {
		t.Fatalf("direct protocol was not restored: %#v", roundtrip.GetProtocols()[0])
	}
}

func TestConvertLegacyNodeBackfillsEmptyChain(t *testing.T) {
	node, warnings, err := ConvertLegacyNode((&legacy.Point_builder{
		Hash:   new("n1"),
		Name:   new("empty"),
		Origin: legacy.Origin_manual.Enum(),
	}).Build())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if got := node.Chain[0].Type; got != "direct" {
		t.Fatalf("protocol type = %q", got)
	}
}

func TestConvertLegacyNodeSkipsEmptyChainEntry(t *testing.T) {
	node, warnings, err := ConvertLegacyNode((&legacy.Point_builder{
		Hash:   new("n1"),
		Name:   new("mixed-empty"),
		Origin: legacy.Origin_manual.Enum(),
		Protocols: []*legacy.Protocol{
			(&legacy.Protocol_builder{Direct: &legacy.Direct{}}).Build(),
			{},
		},
	}).Build())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if len(node.Chain) != 1 || node.Chain[0].Type != "direct" {
		t.Fatalf("chain = %#v", node.Chain)
	}
}

func TestConvertLegacyNodeBackfillsAllEmptyChainEntries(t *testing.T) {
	node, warnings, err := ConvertLegacyNode((&legacy.Point_builder{
		Hash:   new("n1"),
		Name:   new("all-empty"),
		Origin: legacy.Origin_manual.Enum(),
		Protocols: []*legacy.Protocol{
			{},
		},
	}).Build())
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if len(node.Chain) != 1 || node.Chain[0].Type != "direct" {
		t.Fatalf("chain = %#v", node.Chain)
	}
}

func TestConvertLegacyNodeConvertsNestedAEADCryptoMethod(t *testing.T) {
	password := "secret"
	point := (&legacy.Point_builder{
		Hash:   new("n1"),
		Name:   new("split-aead"),
		Origin: legacy.Origin_manual.Enum(),
		Protocols: []*legacy.Protocol{
			(&legacy.Protocol_builder{
				NetworkSplit: (&legacy.NetworkSplit_builder{
					Tcp: (&legacy.Protocol_builder{Direct: &legacy.Direct{}}).Build(),
					Udp: (&legacy.Protocol_builder{Aead: (&legacy.Aead_builder{
						Password:     &password,
						CryptoMethod: legacy.AeadCryptoMethod_XChacha20Poly1305.Enum(),
					}).Build()}).Build(),
				}).Build(),
			}).Build(),
		},
	}).Build()

	node, _, err := ConvertLegacyNode(point)
	if err != nil {
		t.Fatal(err)
	}
	if got := node.Chain[0].NetworkSplit.UDP.AEAD.CryptoMethod; got != "XChacha20Poly1305" {
		t.Fatalf("crypto method = %q", got)
	}

	roundtrip, err := ConvertContractNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundtrip.GetProtocols()[0].GetNetworkSplit().GetUdp().GetAead().GetCryptoMethod(); got != legacy.AeadCryptoMethod_XChacha20Poly1305 {
		t.Fatalf("roundtrip crypto method = %v", got)
	}
}

func TestConvertLegacyNodePreservesPartialNetworkSplit(t *testing.T) {
	password := "secret"
	point := (&legacy.Point_builder{
		Hash:   new("udp-only-split"),
		Name:   new("udp-only-split"),
		Origin: legacy.Origin_manual.Enum(),
		Protocols: []*legacy.Protocol{
			(&legacy.Protocol_builder{
				NetworkSplit: (&legacy.NetworkSplit_builder{
					Udp: (&legacy.Protocol_builder{Aead: (&legacy.Aead_builder{
						Password:     &password,
						CryptoMethod: legacy.AeadCryptoMethod_XChacha20Poly1305.Enum(),
					}).Build()}).Build(),
				}).Build(),
			}).Build(),
		},
	}).Build()

	node, _, err := ConvertLegacyNode(point)
	if err != nil {
		t.Fatal(err)
	}
	if node.Chain[0].NetworkSplit.TCP != nil || node.Chain[0].NetworkSplit.UDP == nil {
		t.Fatalf("network split = %#v", node.Chain[0].NetworkSplit)
	}
	if got := node.Chain[0].NetworkSplit.UDP.AEAD.CryptoMethod; got != "XChacha20Poly1305" {
		t.Fatalf("udp crypto method = %q", got)
	}
}

func TestConvertLegacyNodeConvertsSetStrategy(t *testing.T) {
	point := (&legacy.Point_builder{
		Hash:   new("n1"),
		Name:   new("set"),
		Origin: legacy.Origin_manual.Enum(),
		Protocols: []*legacy.Protocol{
			(&legacy.Protocol_builder{Set: (&legacy.Set_builder{
				Nodes:    []string{"a", "b"},
				Strategy: legacy.Set_round_robin.Enum(),
			}).Build()}).Build(),
		},
	}).Build()

	node, _, err := ConvertLegacyNode(point)
	if err != nil {
		t.Fatal(err)
	}
	if got := node.Chain[0].Set.Strategy; got != "round_robin" {
		t.Fatalf("strategy = %q", got)
	}

	roundtrip, err := ConvertContractNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundtrip.GetProtocols()[0].GetSet().GetStrategy(); got != legacy.Set_round_robin {
		t.Fatalf("roundtrip strategy = %v", got)
	}
}
