package statistic

import (
	json "encoding/json/v2"
	"testing"
)

func TestConnectionUnmarshalLegacyStringUint64(t *testing.T) {
	var got Connection
	if err := json.Unmarshal([]byte(`{
		"addr":"example.com:443",
		"id":"123",
		"type":{"connType":"tcp","underlyingType":"tcp4"},
		"inboundName":"mixed",
		"fakeIp":"198.18.0.1",
		"pid":"456",
		"uid":"789",
		"udpMigrateId":"42",
		"mode":"proxy",
		"matchHistory":[{"ruleName":"default","history":[{"listName":"direct","matched":true}]}]
	}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.Id != 123 {
		t.Fatalf("Id = %d, want 123", got.Id)
	}
	if got.Type == nil || got.Type.ConnType != Type_tcp || got.Type.UnderlyingType != Type_tcp4 {
		t.Fatalf("Type = %#v", got.Type)
	}
	if got.InboundName != "mixed" {
		t.Fatalf("InboundName = %q, want mixed", got.InboundName)
	}
	if got.FakeIp != "198.18.0.1" {
		t.Fatalf("FakeIp = %q, want 198.18.0.1", got.FakeIp)
	}
	if got.Pid != 456 || got.Uid != 789 || got.UdpMigrateId != 42 {
		t.Fatalf("uint64 fields = pid %d uid %d udp %d", got.Pid, got.Uid, got.UdpMigrateId)
	}
	if got.Mode == nil || got.Mode.String() != "proxy" {
		t.Fatalf("Mode = %#v", got.Mode)
	}
	if len(got.MatchHistory) != 1 || got.MatchHistory[0].RuleName != "default" {
		t.Fatalf("MatchHistory = %#v", got.MatchHistory)
	}
	if len(got.MatchHistory[0].History) != 1 || got.MatchHistory[0].History[0].ListName != "direct" || !got.MatchHistory[0].History[0].Matched {
		t.Fatalf("MatchHistory[0].History = %#v", got.MatchHistory[0].History)
	}
}

func TestConnectionUnmarshalPlainStruct(t *testing.T) {
	var got Connection
	if err := json.Unmarshal([]byte(`{
		"addr":"example.com:443",
		"id":123,
		"type":{"conn_type":1,"underlying_type":2},
		"inbound_name":"mixed",
		"fake_ip":"198.18.0.1",
		"pid":456,
		"uid":789,
		"udp_migrate_id":42,
		"mode":2,
		"match_history":[{"rule_name":"default","history":[{"list_name":"direct","matched":true}]}]
	}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.Id != 123 {
		t.Fatalf("Id = %d, want 123", got.Id)
	}
	if got.Type == nil || got.Type.ConnType != Type_tcp || got.Type.UnderlyingType != Type_tcp4 {
		t.Fatalf("Type = %#v", got.Type)
	}
	if got.InboundName != "mixed" || got.FakeIp != "198.18.0.1" {
		t.Fatalf("names = inbound %q fake %q", got.InboundName, got.FakeIp)
	}
	if got.Mode == nil || got.Mode.String() != "proxy" {
		t.Fatalf("Mode = %#v", got.Mode)
	}
	if len(got.MatchHistory) != 1 || got.MatchHistory[0].RuleName != "default" {
		t.Fatalf("MatchHistory = %#v", got.MatchHistory)
	}
}
