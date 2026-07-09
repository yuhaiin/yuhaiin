package node

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (x *NatType) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, NatType_value)
	if err != nil {
		return err
	}
	*x = NatType(v)
	return nil
}

func (x *Origin) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, Origin_value)
	if err != nil {
		return err
	}
	*x = Origin(v)
	return nil
}

func (x *AeadCryptoMethod) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, AeadCryptoMethod_value)
	if err != nil {
		return err
	}
	*x = AeadCryptoMethod(v)
	return nil
}

func (x *SetStrategyType) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, SetStrategyType_value)
	if err != nil {
		return err
	}
	*x = SetStrategyType(v)
	return nil
}

func (x *Type) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, Type_value)
	if err != nil {
		return err
	}
	*x = Type(v)
	return nil
}

func (x *TagType) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, TagType_value)
	if err != nil {
		return err
	}
	*x = TagType(v)
	return nil
}

func (x *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		d, err := time.ParseDuration(s)
		if err == nil {
			x.Seconds = int64(d / time.Second)
			x.Nanos = int32(d % time.Second)
			return nil
		}
		seconds, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		x.Seconds = seconds
		x.Nanos = 0
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	seconds, err := legacyInt64(raw, "seconds")
	if err != nil {
		return fmt.Errorf("seconds: %w", err)
	}
	nanos, err := legacyInt32(raw, "nanos")
	if err != nil {
		return fmt.Errorf("nanos: %w", err)
	}
	x.Seconds = seconds
	x.Nanos = nanos
	return nil
}

func (x *Protocol) UnmarshalJSON(data []byte) error {
	type protocolAlias Protocol
	var alias protocolAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = Protocol(alias)

	if x.WhichProtocol() != Protocol_Protocol_not_set_case {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cases := []string{
		"shadowsocks", "shadowsocksr", "vmess", "websocket", "quic", "obfsHttp", "obfs_http", "trojan",
		"simple", "none", "socks5", "http", "direct", "reject", "yuubinsya", "http2", "reality", "tls",
		"wireguard", "mux", "drop", "vless", "bootstrapDnsWarp", "bootstrap_dns_warp", "tailscale", "set",
		"tlsTermination", "tls_termination", "httpTermination", "http_termination", "httpMock", "http_mock",
		"aead", "fixed", "networkSplit", "network_split", "cloudflareWarpMasque", "cloudflare_warp_masque",
		"proxy", "fixedv2", "pointAsEndpoint", "point_as_endpoint",
	}
	if err := legacyOneof(legacyRawValue(raw, "protocol"), cases, x.setProtocolOneof); err != nil {
		return err
	}
	if x.WhichProtocol() == Protocol_Protocol_not_set_case {
		return legacyDirectOneof(raw, cases, x.setProtocolOneof)
	}
	return nil
}

func (x *RequestProtocol) UnmarshalJSON(data []byte) error {
	type requestProtocolAlias RequestProtocol
	var alias requestProtocolAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = RequestProtocol(alias)

	if x.WhichProtocol() != RequestProtocol_Protocol_not_set_case {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cases := []string{"http", "dns", "dnsOverQuic", "dns_over_quic", "ip", "stun"}
	if err := legacyOneof(legacyRawValue(raw, "protocol"), cases, x.setProtocolOneof); err != nil {
		return err
	}
	if x.WhichProtocol() == RequestProtocol_Protocol_not_set_case {
		return legacyDirectOneof(raw, cases, x.setProtocolOneof)
	}
	return nil
}

func (x *RequestProtocol) setProtocolOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "http":
		x.Http = &HttpTest{}
		return unmarshalOneof(data, x.Http, "http")
	case "dns":
		x.Dns = &DnsTest{}
		return unmarshalOneof(data, x.Dns, "dns")
	case "dnsoverquic":
		x.DnsOverQuic = &DnsOverQuic{}
		return unmarshalOneof(data, x.DnsOverQuic, "dns_over_quic")
	case "ip":
		x.Ip = &Ip{}
		return unmarshalOneof(data, x.Ip, "ip")
	case "stun":
		x.Stun = &Stun{}
		return unmarshalOneof(data, x.Stun, "stun")
	}
	return nil
}

func (x *Reply) UnmarshalJSON(data []byte) error {
	type replyAlias Reply
	var alias replyAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = Reply(alias)

	if x.WhichReply() != Reply_Reply_not_set_case {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cases := []string{"latency", "ip", "stun", "error"}
	if err := legacyOneof(legacyRawValue(raw, "reply"), cases, x.setReplyOneof); err != nil {
		return err
	}
	if x.WhichReply() == Reply_Reply_not_set_case {
		return legacyDirectOneof(raw, cases, x.setReplyOneof)
	}
	return nil
}

func (x *Reply) setReplyOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "latency":
		x.Latency = &Duration{}
		return unmarshalOneof(data, x.Latency, "latency")
	case "ip":
		x.Ip = &IpResponse{}
		return unmarshalOneof(data, x.Ip, "ip")
	case "stun":
		x.Stun = &StunResponse{}
		return unmarshalOneof(data, x.Stun, "stun")
	case "error":
		x.Error = &Error{}
		return unmarshalOneof(data, x.Error, "error")
	}
	return nil
}

func (x *YuhaiinUrl) UnmarshalJSON(data []byte) error {
	type yuhaiinURLAlias YuhaiinUrl
	var alias yuhaiinURLAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = YuhaiinUrl(alias)

	if x.WhichUrl() != YuhaiinUrl_Url_not_set_case {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cases := []string{"remote", "points"}
	if err := legacyOneof(legacyRawValue(raw, "url"), cases, x.setURLOneof); err != nil {
		return err
	}
	if x.WhichUrl() == YuhaiinUrl_Url_not_set_case {
		return legacyDirectOneof(raw, cases, x.setURLOneof)
	}
	return nil
}

func (x *YuhaiinUrl) setURLOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "remote":
		x.Remote = &YuhaiinUrl_Remote{}
		return unmarshalOneof(data, x.Remote, "remote")
	case "points":
		x.Points = &YuhaiinUrl_Points{}
		return unmarshalOneof(data, x.Points, "points")
	}
	return nil
}

func (x *Protocol) setProtocolOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "shadowsocks":
		x.Shadowsocks = &Shadowsocks{}
		return unmarshalOneof(data, x.Shadowsocks, "shadowsocks")
	case "shadowsocksr":
		x.Shadowsocksr = &Shadowsocksr{}
		return unmarshalOneof(data, x.Shadowsocksr, "shadowsocksr")
	case "vmess":
		x.Vmess = &Vmess{}
		return unmarshalOneof(data, x.Vmess, "vmess")
	case "websocket":
		x.Websocket = &Websocket{}
		return unmarshalOneof(data, x.Websocket, "websocket")
	case "quic":
		x.Quic = &Quic{}
		return unmarshalOneof(data, x.Quic, "quic")
	case "obfshttp":
		x.ObfsHttp = &ObfsHttp{}
		return unmarshalOneof(data, x.ObfsHttp, "obfs_http")
	case "trojan":
		x.Trojan = &Trojan{}
		return unmarshalOneof(data, x.Trojan, "trojan")
	case "simple":
		x.Simple = &Simple{}
		return unmarshalOneof(data, x.Simple, "simple")
	case "none":
		x.None = &None{}
		return unmarshalOneof(data, x.None, "none")
	case "socks5":
		x.Socks5 = &Socks5{}
		return unmarshalOneof(data, x.Socks5, "socks5")
	case "http":
		x.Http = &Http{}
		return unmarshalOneof(data, x.Http, "http")
	case "direct":
		x.Direct = &Direct{}
		return unmarshalOneof(data, x.Direct, "direct")
	case "reject":
		x.Reject = &Reject{}
		return unmarshalOneof(data, x.Reject, "reject")
	case "yuubinsya":
		x.Yuubinsya = &Yuubinsya{}
		return unmarshalOneof(data, x.Yuubinsya, "yuubinsya")
	case "http2":
		x.Http2 = &Http2{}
		return unmarshalOneof(data, x.Http2, "http2")
	case "reality":
		x.Reality = &Reality{}
		return unmarshalOneof(data, x.Reality, "reality")
	case "tls":
		x.Tls = &TlsConfig{}
		return unmarshalOneof(data, x.Tls, "tls")
	case "wireguard":
		x.Wireguard = &Wireguard{}
		return unmarshalOneof(data, x.Wireguard, "wireguard")
	case "mux":
		x.Mux = &Mux{}
		return unmarshalOneof(data, x.Mux, "mux")
	case "drop":
		x.Drop = &Drop{}
		return unmarshalOneof(data, x.Drop, "drop")
	case "vless":
		x.Vless = &Vless{}
		return unmarshalOneof(data, x.Vless, "vless")
	case "bootstrapdnswarp":
		x.BootstrapDnsWarp = &BootstrapDnsWarp{}
		return unmarshalOneof(data, x.BootstrapDnsWarp, "bootstrap_dns_warp")
	case "tailscale":
		x.Tailscale = &Tailscale{}
		return unmarshalOneof(data, x.Tailscale, "tailscale")
	case "set":
		x.Set = &Set{}
		return unmarshalOneof(data, x.Set, "set")
	case "tlstermination":
		x.TlsTermination = &TlsTermination{}
		return unmarshalOneof(data, x.TlsTermination, "tls_termination")
	case "httptermination":
		x.HttpTermination = &HttpTermination{}
		return unmarshalOneof(data, x.HttpTermination, "http_termination")
	case "httpmock":
		x.HttpMock = &HttpMock{}
		return unmarshalOneof(data, x.HttpMock, "http_mock")
	case "aead":
		x.Aead = &Aead{}
		return unmarshalOneof(data, x.Aead, "aead")
	case "fixed":
		x.Fixed = &Fixed{}
		return unmarshalOneof(data, x.Fixed, "fixed")
	case "networksplit":
		x.NetworkSplit = &NetworkSplit{}
		return unmarshalOneof(data, x.NetworkSplit, "network_split")
	case "cloudflarewarpmasque":
		x.CloudflareWarpMasque = &CloudflareWarpMasque{}
		return unmarshalOneof(data, x.CloudflareWarpMasque, "cloudflare_warp_masque")
	case "proxy":
		x.Proxy = &Proxy{}
		return unmarshalOneof(data, x.Proxy, "proxy")
	case "fixedv2":
		x.Fixedv2 = &Fixedv2{}
		return unmarshalOneof(data, x.Fixedv2, "fixedv2")
	case "pointasendpoint":
		x.PointAsEndpoint = &PointAsEndpoint{}
		return unmarshalOneof(data, x.PointAsEndpoint, "point_as_endpoint")
	}
	return nil
}

func legacyEnum(data []byte, values map[string]int32) (int32, error) {
	var n int32
	if err := json.Unmarshal(data, &n); err == nil {
		return n, nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return 0, err
	}
	if v, ok := values[s]; ok {
		return v, nil
	}
	if n64, err := strconv.ParseInt(s, 10, 32); err == nil {
		return int32(n64), nil
	}
	return 0, fmt.Errorf("unknown enum value %q", s)
}

func legacyInt64(raw map[string]jsontext.Value, names ...string) (int64, error) {
	v := legacyRawValue(raw, names...)
	if len(v) == 0 || string(v) == "null" {
		return 0, nil
	}
	var n int64
	if err := json.Unmarshal(v, &n); err == nil {
		return n, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return 0, err
	}
	return strconv.ParseInt(s, 10, 64)
}

func legacyInt32(raw map[string]jsontext.Value, names ...string) (int32, error) {
	v, err := legacyInt64(raw, names...)
	return int32(v), err
}

func legacyRawValue(raw map[string]jsontext.Value, names ...string) jsontext.Value {
	for _, name := range names {
		if v, ok := raw[name]; ok {
			return v
		}
	}
	return nil
}

func legacyOneof(data jsontext.Value, cases []string, set func(string, jsontext.Value) error) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var caseName string
	if v := legacyRawValue(raw, "case"); len(v) != 0 {
		if err := json.Unmarshal(v, &caseName); err != nil {
			return fmt.Errorf("case: %w", err)
		}
	}
	value := legacyRawValue(raw, "value")
	if caseName != "" {
		if len(value) == 0 {
			value = jsontext.Value("{}")
		}
		return set(caseName, value)
	}
	return legacyDirectOneof(raw, cases, set)
}

func legacyDirectOneof(raw map[string]jsontext.Value, cases []string, set func(string, jsontext.Value) error) error {
	for _, name := range cases {
		if v := legacyRawValue(raw, name); len(v) != 0 && string(v) != "null" {
			return set(name, v)
		}
	}
	return nil
}

func normalizedOneofCase(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", ""))
}

func unmarshalOneof(data jsontext.Value, dst any, name string) error {
	if len(data) == 0 || string(data) == "null" {
		data = jsontext.Value("{}")
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
