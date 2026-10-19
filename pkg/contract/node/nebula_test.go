package node

import (
	"encoding/json/v2"
	"testing"
)

func TestNebulaTaggedJSONRoundTrip(t *testing.T) {
	const conf = "pki:\n  ca: embedded\n  cert: embedded\n  key: embedded\n"
	p, err := NewTypedProtocol(Nebula{ConfigYAML: conf})
	if err != nil { t.Fatal(err) }
	if err := p.Validate(); err != nil { t.Fatal(err) }
	data, err := json.Marshal(p)
	if err != nil { t.Fatal(err) }
	var decoded Protocol
	if err := json.Unmarshal(data, &decoded); err != nil { t.Fatal(err) }
	if err := decoded.Validate(); err != nil { t.Fatal(err) }
	if decoded.Type != "nebula" || decoded.Nebula == nil || decoded.Nebula.ConfigYAML != conf {
		t.Fatalf("nebula config did not round-trip: %+v", decoded)
	}
}
