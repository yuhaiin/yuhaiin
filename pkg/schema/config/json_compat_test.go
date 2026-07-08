package config

import (
	json "encoding/json/v2"
	"testing"
)

func TestRefreshConfigUnmarshalLegacyStringUint64(t *testing.T) {
	var got RefreshConfig
	if err := json.Unmarshal([]byte(`{"refresh_interval":"3600","last_refresh_time":"100","error":"ok"}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.RefreshInterval != 3600 {
		t.Fatalf("RefreshInterval = %d, want 3600", got.RefreshInterval)
	}
	if got.LastRefreshTime != 100 {
		t.Fatalf("LastRefreshTime = %d, want 100", got.LastRefreshTime)
	}
	if got.Error != "ok" {
		t.Fatalf("Error = %q, want ok", got.Error)
	}
}

func TestConfigEnumsUnmarshalLegacyStringValues(t *testing.T) {
	var dns Dns
	if err := json.Unmarshal([]byte(`{"type":"udp","host":"223.5.5.5"}`), &dns); err != nil {
		t.Fatalf("unmarshal dns failed: %v", err)
	}
	if dns.Type != Type_udp {
		t.Fatalf("dns.Type = %v, want %v", dns.Type, Type_udp)
	}

	var mode ModeConfig
	if err := json.Unmarshal([]byte(`{"mode":"proxy","resolve_strategy":"prefer_ipv4"}`), &mode); err != nil {
		t.Fatalf("unmarshal mode failed: %v", err)
	}
	if mode.Mode != Mode_proxy {
		t.Fatalf("mode.Mode = %v, want %v", mode.Mode, Mode_proxy)
	}
	if mode.ResolveStrategy != ResolveStrategy_prefer_ipv4 {
		t.Fatalf("mode.ResolveStrategy = %v, want %v", mode.ResolveStrategy, ResolveStrategy_prefer_ipv4)
	}

	var logcat Logcat
	if err := json.Unmarshal([]byte(`{"level":"warning"}`), &logcat); err != nil {
		t.Fatalf("unmarshal logcat failed: %v", err)
	}
	if logcat.Level != LogLevel_warning {
		t.Fatalf("logcat.Level = %v, want %v", logcat.Level, LogLevel_warning)
	}
}

func TestBackupOptionUnmarshalLegacyStringUint64(t *testing.T) {
	var got BackupOption
	if err := json.Unmarshal([]byte(`{"instance_name":"main","interval":"30","last_backup_hash":"abc"}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.InstanceName != "main" {
		t.Fatalf("InstanceName = %q, want main", got.InstanceName)
	}
	if got.Interval != 30 {
		t.Fatalf("Interval = %d, want 30", got.Interval)
	}
	if got.LastBackupHash != "abc" {
		t.Fatalf("LastBackupHash = %q, want abc", got.LastBackupHash)
	}
}

func TestConfigVersionUnmarshalLegacyStringUint64(t *testing.T) {
	var got ConfigVersion
	if err := json.Unmarshal([]byte(`{"version":"12"}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.Version != 12 {
		t.Fatalf("Version = %d, want 12", got.Version)
	}
}

func TestRemoteRuleUnmarshalLegacyOneofWrapper(t *testing.T) {
	var got RemoteRule
	if err := json.Unmarshal([]byte(`{"object":{"case":"http","value":{"url":"https://example.test/rules","method":"GET"}}}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichObject() != RemoteRule_Http_case {
		t.Fatalf("WhichObject = %v, want %v", got.WhichObject(), RemoteRule_Http_case)
	}
	if got.GetHttp().GetUrl() != "https://example.test/rules" {
		t.Fatalf("url = %q, want https://example.test/rules", got.GetHttp().GetUrl())
	}
}

func TestRuleUnmarshalLegacyOneofWrapper(t *testing.T) {
	var got Rule
	if err := json.Unmarshal([]byte(`{"object":{"case":"network","value":{"network":"tcp"}}}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichObject() != Rule_Network_case {
		t.Fatalf("WhichObject = %v, want %v", got.WhichObject(), Rule_Network_case)
	}
	if got.GetNetwork().GetNetwork() != Network_tcp {
		t.Fatalf("network = %v, want %v", got.GetNetwork().GetNetwork(), Network_tcp)
	}
}

func TestListUnmarshalLegacyOneofWrapper(t *testing.T) {
	var got List
	err := json.Unmarshal([]byte(`{
		"name":"transmission-block",
		"type":"host",
		"list":{"case":"remote","value":{"urls":["https://example.test/list.txt"]}}
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichList() != List_Remote_case {
		t.Fatalf("WhichList = %v, want %v", got.WhichList(), List_Remote_case)
	}
	if got.Remote == nil || len(got.Remote.Urls) != 1 || got.Remote.Urls[0] != "https://example.test/list.txt" {
		t.Fatalf("Remote = %#v", got.Remote)
	}
}

func TestListUnmarshalPlainStruct(t *testing.T) {
	var got List
	err := json.Unmarshal([]byte(`{
		"name":"local-hosts",
		"type":"host",
		"local":{"lists":["example.com"]}
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichList() != List_Local_case {
		t.Fatalf("WhichList = %v, want %v", got.WhichList(), List_Local_case)
	}
	if got.Local == nil || len(got.Local.Lists) != 1 || got.Local.Lists[0] != "example.com" {
		t.Fatalf("Local = %#v", got.Local)
	}
}

func TestInboundUnmarshalLegacyOneofWrappers(t *testing.T) {
	var got Inbound
	err := json.Unmarshal([]byte(`{
		"name":"mixed",
		"enabled":true,
		"network":{"case":"tcpudp","value":{"host":"127.0.0.1","port":1080}},
		"protocol":{"case":"mix","value":{}},
		"transport":[
			{"transport":{"case":"tls","value":{}}},
			{"transport":{"case":"tlsAuto","value":{}}}
		]
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichNetwork() != Inbound_Tcpudp_case {
		t.Fatalf("WhichNetwork = %v, want %v", got.WhichNetwork(), Inbound_Tcpudp_case)
	}
	if got.WhichProtocol() != Inbound_Mix_case {
		t.Fatalf("WhichProtocol = %v, want %v", got.WhichProtocol(), Inbound_Mix_case)
	}
	if len(got.Transport) != 2 {
		t.Fatalf("len(Transport) = %d, want 2", len(got.Transport))
	}
	if got.Transport[0].WhichTransport() != Transport_Tls_case {
		t.Fatalf("Transport[0] = %v, want %v", got.Transport[0].WhichTransport(), Transport_Tls_case)
	}
	if got.Transport[1].WhichTransport() != Transport_TlsAuto_case {
		t.Fatalf("Transport[1] = %v, want %v", got.Transport[1].WhichTransport(), Transport_TlsAuto_case)
	}
}

func TestInboundUnmarshalLegacyReverseHTTPWrapper(t *testing.T) {
	var got Inbound
	err := json.Unmarshal([]byte(`{
		"name":"reversehttp",
		"network":{"case":"Tcpudp","value":{}},
		"protocol":{"case":"ReverseHttp","value":{}}
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichProtocol() != Inbound_ReverseHttp_case {
		t.Fatalf("WhichProtocol = %v, want %v", got.WhichProtocol(), Inbound_ReverseHttp_case)
	}
}

func TestInboundUnmarshalPlainStruct(t *testing.T) {
	var got Inbound
	err := json.Unmarshal([]byte(`{
		"name":"plain",
		"tcpudp":{},
		"yuubinsya":{},
		"transport":[{"normal":{}}]
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichNetwork() != Inbound_Tcpudp_case {
		t.Fatalf("WhichNetwork = %v, want %v", got.WhichNetwork(), Inbound_Tcpudp_case)
	}
	if got.WhichProtocol() != Inbound_Yuubinsya_case {
		t.Fatalf("WhichProtocol = %v, want %v", got.WhichProtocol(), Inbound_Yuubinsya_case)
	}
	if len(got.Transport) != 1 || got.Transport[0].WhichTransport() != Transport_Normal_case {
		t.Fatalf("Transport = %#v", got.Transport)
	}
}

func TestInboundUnmarshalLegacyProtoJSONSnakeOneofs(t *testing.T) {
	var got Inbound
	err := json.Unmarshal([]byte(`{
		"name":"tlsAuth",
		"enabled":true,
		"tcpudp":{"host":":9099","control":"disable_udp","udp_happy_eyeballs":null},
		"transport":[{"tls_auto":{"servernames":["*.hicloud.com"],"next_protos":[]}}],
		"yuubinsya":{"password":"secret","udp_coalesce":null}
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichProtocol() != Inbound_Yuubinsya_case {
		t.Fatalf("WhichProtocol = %v, want %v", got.WhichProtocol(), Inbound_Yuubinsya_case)
	}
	if len(got.Transport) != 1 || got.Transport[0].WhichTransport() != Transport_TlsAuto_case {
		t.Fatalf("Transport = %#v", got.Transport)
	}
}

func TestInboundUnmarshalLegacyProtoJSONReverseSnakeOneof(t *testing.T) {
	var got Inbound
	err := json.Unmarshal([]byte(`{
		"name":"win11-rdp",
		"enabled":true,
		"tcpudp":{"host":":3389","control":"disable_udp","udp_happy_eyeballs":null},
		"transport":[],
		"reverse_tcp":{"host":"192.168.100.176:3389"}
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichProtocol() != Inbound_ReverseTcp_case {
		t.Fatalf("WhichProtocol = %v, want %v", got.WhichProtocol(), Inbound_ReverseTcp_case)
	}
}

func TestInboundUnmarshalLegacyProtoJSONMixedAlias(t *testing.T) {
	var got Inbound
	err := json.Unmarshal([]byte(`{
		"name":"mixed",
		"enabled":true,
		"tcpudp":{"host":"0.0.0.0:1080","control":"tcp_udp_control_all","udp_happy_eyeballs":null},
		"transport":[],
		"mixed":{"username":"","password":""}
	}`), &got)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.WhichProtocol() != Inbound_Mix_case {
		t.Fatalf("WhichProtocol = %v, want %v", got.WhichProtocol(), Inbound_Mix_case)
	}
}
