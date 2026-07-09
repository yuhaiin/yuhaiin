package migrate

import (
	"testing"

	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

func TestConvertLegacyNodeUsesChain(t *testing.T) {
	point := (&legacy.Point_builder{
		Hash:   ptr("n1"),
		Name:   ptr("direct"),
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
		Hash:   ptr("n1"),
		Name:   ptr("empty"),
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
		Hash:   ptr("n1"),
		Name:   ptr("mixed-empty"),
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
		Hash:   ptr("n1"),
		Name:   ptr("all-empty"),
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
