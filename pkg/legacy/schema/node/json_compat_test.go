package node

import (
	json "encoding/json/v2"
	"testing"
)

func TestRequestProtocolUnmarshalLegacyWrapper(t *testing.T) {
	var got RequestProtocol
	if err := json.Unmarshal([]byte(`{"protocol":{"case":"dnsOverQuic","value":{"host":"1.1.1.1","target_domain":"example.com"}}}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichProtocol() != RequestProtocol_DnsOverQuic_case {
		t.Fatalf("WhichProtocol = %v, want %v", got.WhichProtocol(), RequestProtocol_DnsOverQuic_case)
	}
	if got.GetDnsOverQuic().GetHost() != "1.1.1.1" {
		t.Fatalf("host = %q, want 1.1.1.1", got.GetDnsOverQuic().GetHost())
	}
}

func TestReplyUnmarshalLegacyWrapper(t *testing.T) {
	var got Reply
	if err := json.Unmarshal([]byte(`{"reply":{"case":"error","value":{"msg":"unsupported operation"}}}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichReply() != Reply_Error_case {
		t.Fatalf("WhichReply = %v, want %v", got.WhichReply(), Reply_Error_case)
	}
	if got.GetError().GetMsg() != "unsupported operation" {
		t.Fatalf("msg = %q, want unsupported operation", got.GetError().GetMsg())
	}
}

func TestDurationUnmarshalLegacyStringInt64(t *testing.T) {
	var got Duration
	if err := json.Unmarshal([]byte(`{"seconds":"12","nanos":"34"}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.Seconds != 12 || got.Nanos != 34 {
		t.Fatalf("Duration = %+v, want seconds 12 nanos 34", got)
	}
}

func TestDurationUnmarshalLegacyNanosRejectsInt32Overflow(t *testing.T) {
	var got Duration
	err := json.Unmarshal([]byte(`{"seconds":"12","nanos":"2147483648"}`), &got)
	if err == nil {
		t.Fatal("unmarshal succeeded for an int32-overflowing nanos value")
	}
}

func TestDurationUnmarshalProtobufDurationString(t *testing.T) {
	var got Duration
	if err := json.Unmarshal([]byte(`"1.5s"`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.Seconds != 1 || got.Nanos != 500_000_000 {
		t.Fatalf("Duration = %+v, want seconds 1 nanos 500000000", got)
	}
}

func TestYuhaiinURLUnmarshalLegacyWrapper(t *testing.T) {
	var got YuhaiinUrl
	if err := json.Unmarshal([]byte(`{
		"name":"share",
		"url":{"case":"remote","value":{"publish":{"name":"share","address":"example.com"}}}
	}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichUrl() != YuhaiinUrl_Remote_case {
		t.Fatalf("WhichUrl = %v, want %v", got.WhichUrl(), YuhaiinUrl_Remote_case)
	}
	if got.GetRemote().GetPublish().GetAddress() != "example.com" {
		t.Fatalf("address = %q, want example.com", got.GetRemote().GetPublish().GetAddress())
	}
}
