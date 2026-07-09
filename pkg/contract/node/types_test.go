package node

import (
	json "encoding/json/v2"
	"strings"
	"testing"
)

func TestProtocolTaggedObjectJSON(t *testing.T) {
	protocol, err := NewProtocol("direct", nil)
	if err != nil {
		t.Fatal(err)
	}
	node := Node{
		ID:      "node-1",
		Name:    "direct",
		Origin:  "manual",
		Enabled: true,
		Chain:   []Protocol{protocol},
	}
	if err := node.Validate(); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"chain":[{"type":"direct","direct":{}}]`) {
		t.Fatalf("unexpected json: %s", text)
	}
	if strings.Contains(text, "protocols") || strings.Contains(text, "case") || strings.Contains(text, "value") {
		t.Fatalf("protobuf-shaped field leaked into json: %s", text)
	}

	var decoded Node
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolRejectsMismatch(t *testing.T) {
	if err := (Protocol{Type: "direct", Reject: &Reject{}}).Validate(); err == nil {
		t.Fatal("expected mismatch error")
	}
	if err := (Protocol{Type: "direct", Direct: &Direct{}, Reject: &Reject{}}).Validate(); err == nil {
		t.Fatal("expected duplicate concrete object error")
	}
}
