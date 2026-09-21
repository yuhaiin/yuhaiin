package migrate

import (
	"encoding/json/jsontext"
	"reflect"
	"testing"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestRecoverPartialNetworkSplitsPreservesExistingProtocolOrder(t *testing.T) {
	password := "secret"
	legacy := legacyconfigPointForPartialNetworkSplit(password)
	expected, _, err := ConvertLegacyNode(legacy)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := contractnode.NewTypedProtocol(contractnode.Proxy{})
	if err != nil {
		t.Fatal(err)
	}
	yuubinsya, err := contractnode.NewTypedProtocol(contractnode.Yuubinsya{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	current := []contractnode.Protocol{proxy, yuubinsya}

	got, changed := recoverPartialNetworkSplits(current, expected.Chain)
	if !changed {
		t.Fatal("partial network_split was not restored")
	}
	gotTypes := protocolTypes(got)
	if want := []string{"proxy", "network_split", "yuubinsya"}; !reflect.DeepEqual(gotTypes, want) {
		t.Fatalf("recovered protocol order = %v, want %v", gotTypes, want)
	}

	current = []contractnode.Protocol{proxy, expected.Chain[0], yuubinsya}
	got, changed = recoverPartialNetworkSplits(current, expected.Chain)
	if changed || !reflect.DeepEqual(got, current) {
		t.Fatalf("existing network_split was duplicated or reordered: changed=%v chain=%v", changed, protocolTypes(got))
	}
}

func TestRecoverLegacyTransportsPreservesCurrentOrder(t *testing.T) {
	current := []contractinbound.Transport{
		contractinbound.NewTypedTransport(contractinbound.TLSAutoTransport{}),
		contractinbound.NewTypedTransport(contractinbound.HTTP2Transport{}),
	}
	raw := []map[string]jsontext.Value{
		{"proxy": jsontext.Value("{}")},
		{"http2": jsontext.Value("{}")},
	}

	got, changed, err := recoverLegacyTransports(current, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("missing transport was not restored")
	}
	gotTypes := transportTypes(got)
	if want := []string{"tls_auto", "proxy", "http2"}; !reflect.DeepEqual(gotTypes, want) {
		t.Fatalf("recovered transport order = %v, want %v", gotTypes, want)
	}
}

func protocolTypes(protocols []contractnode.Protocol) []string {
	types := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		types = append(types, protocol.Type)
	}
	return types
}

func transportTypes(transports []contractinbound.Transport) []string {
	types := make([]string, 0, len(transports))
	for _, transport := range transports {
		types = append(types, transport.Type)
	}
	return types
}
