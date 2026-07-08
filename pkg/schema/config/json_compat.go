package config

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strconv"
	"strings"
)

func (x *Mode) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, Mode_value)
	if err != nil {
		return err
	}
	*x = Mode(v)
	return nil
}

func (x *ResolveStrategy) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, ResolveStrategy_value)
	if err != nil {
		return err
	}
	*x = ResolveStrategy(v)
	return nil
}

func (x *UdpProxyFqdnStrategy) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, UdpProxyFqdnStrategy_value)
	if err != nil {
		return err
	}
	*x = UdpProxyFqdnStrategy(v)
	return nil
}

func (x *NetworkNetworkType) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, NetworkNetworkType_value)
	if err != nil {
		return err
	}
	*x = NetworkNetworkType(v)
	return nil
}

func (x *ListListTypeEnum) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, ListListTypeEnum_value)
	if err != nil {
		return err
	}
	*x = ListListTypeEnum(v)
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

func (x *TcpUdpControl) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, TcpUdpControl_value)
	if err != nil {
		return err
	}
	*x = TcpUdpControl(v)
	return nil
}

func (x *TunEndpointDriver) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, TunEndpointDriver_value)
	if err != nil {
		return err
	}
	*x = TunEndpointDriver(v)
	return nil
}

func (x *LogLevel) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, LogLevel_value)
	if err != nil {
		return err
	}
	*x = LogLevel(v)
	return nil
}

func (x *RefreshConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	refreshInterval, err := legacyUint64(raw, "refresh_interval", "refreshInterval")
	if err != nil {
		return fmt.Errorf("refresh_interval: %w", err)
	}
	lastRefreshTime, err := legacyUint64(raw, "last_refresh_time", "lastRefreshTime")
	if err != nil {
		return fmt.Errorf("last_refresh_time: %w", err)
	}

	x.RefreshInterval = refreshInterval
	x.LastRefreshTime = lastRefreshTime
	if v := legacyRawValue(raw, "error"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.Error); err != nil {
			return fmt.Errorf("error: %w", err)
		}
	}
	return nil
}

func (x *BackupOption) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if v := legacyRawValue(raw, "instance_name", "instanceName"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.InstanceName); err != nil {
			return fmt.Errorf("instance_name: %w", err)
		}
	}
	if v := legacyRawValue(raw, "s3"); len(v) != 0 && string(v) != "null" {
		x.S3 = &S3{}
		if err := json.Unmarshal(v, x.S3); err != nil {
			return fmt.Errorf("s3: %w", err)
		}
	}
	interval, err := legacyUint64(raw, "interval")
	if err != nil {
		return fmt.Errorf("interval: %w", err)
	}
	x.Interval = interval
	if v := legacyRawValue(raw, "last_backup_hash", "lastBackupHash"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.LastBackupHash); err != nil {
			return fmt.Errorf("last_backup_hash: %w", err)
		}
	}
	return nil
}

func (x *ConfigVersion) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	version, err := legacyUint64(raw, "version")
	if err != nil {
		return fmt.Errorf("version: %w", err)
	}
	x.Version = version
	return nil
}

func (x *RemoteRule) UnmarshalJSON(data []byte) error {
	type remoteRuleAlias RemoteRule
	var alias remoteRuleAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = RemoteRule(alias)

	if x.WhichObject() != RemoteRule_Object_not_set_case {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cases := []string{"file", "http"}
	if err := legacyOneof(legacyRawValue(raw, "object"), cases, x.setObjectOneof); err != nil {
		return err
	}
	if x.WhichObject() == RemoteRule_Object_not_set_case {
		return legacyDirectOneof(raw, cases, x.setObjectOneof)
	}
	return nil
}

func (x *RemoteRule) setObjectOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "file":
		x.File = &RemoteRuleFile{}
		if err := json.Unmarshal(data, x.File); err != nil {
			return fmt.Errorf("file: %w", err)
		}
	case "http":
		x.Http = &RemoteRuleHttp{}
		if err := json.Unmarshal(data, x.Http); err != nil {
			return fmt.Errorf("http: %w", err)
		}
	}
	return nil
}

func (x *Rule) UnmarshalJSON(data []byte) error {
	type ruleAlias Rule
	var alias ruleAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = Rule(alias)

	if x.WhichObject() != Rule_Object_not_set_case {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cases := []string{"host", "process", "inbound", "network", "port", "geoip"}
	if err := legacyOneof(legacyRawValue(raw, "object"), cases, x.setObjectOneof); err != nil {
		return err
	}
	if x.WhichObject() == Rule_Object_not_set_case {
		return legacyDirectOneof(raw, cases, x.setObjectOneof)
	}
	return nil
}

func (x *Rule) setObjectOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "host":
		x.Host = &Host{}
		if err := json.Unmarshal(data, x.Host); err != nil {
			return fmt.Errorf("host: %w", err)
		}
	case "process":
		x.Process = &Process{}
		if err := json.Unmarshal(data, x.Process); err != nil {
			return fmt.Errorf("process: %w", err)
		}
	case "inbound":
		x.Inbound = &Source{}
		if err := json.Unmarshal(data, x.Inbound); err != nil {
			return fmt.Errorf("inbound: %w", err)
		}
	case "network":
		x.Network = &Network{}
		if err := json.Unmarshal(data, x.Network); err != nil {
			return fmt.Errorf("network: %w", err)
		}
	case "port":
		x.Port = &Port{}
		if err := json.Unmarshal(data, x.Port); err != nil {
			return fmt.Errorf("port: %w", err)
		}
	case "geoip":
		x.Geoip = &Geoip{}
		if err := json.Unmarshal(data, x.Geoip); err != nil {
			return fmt.Errorf("geoip: %w", err)
		}
	}
	return nil
}

func (x *List) UnmarshalJSON(data []byte) error {
	type listAlias List
	var alias listAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = List(alias)

	if x.Local != nil || x.Remote != nil {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	return legacyOneof(legacyRawValue(raw, "list"), []string{"local", "remote"}, x.setListOneof)
}

func (x *List) setListOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "local":
		x.Local = &ListLocal{}
		if err := json.Unmarshal(data, x.Local); err != nil {
			return fmt.Errorf("local: %w", err)
		}
	case "remote":
		x.Remote = &ListRemote{}
		if err := json.Unmarshal(data, x.Remote); err != nil {
			return fmt.Errorf("remote: %w", err)
		}
	}
	return nil
}

func (x *Inbound) UnmarshalJSON(data []byte) error {
	type inboundAlias Inbound
	var alias inboundAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = Inbound(alias)

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if x.WhichNetwork() == Inbound_Network_not_set_case {
		if err := legacyOneof(legacyRawValue(raw, "network"), []string{"empty", "tcpudp", "quic"}, x.setNetworkOneof); err != nil {
			return err
		}
	}
	if x.WhichNetwork() == Inbound_Network_not_set_case {
		if err := legacyDirectOneof(raw, []string{"empty", "tcpudp", "quic"}, x.setNetworkOneof); err != nil {
			return err
		}
	}
	if x.WhichProtocol() == Inbound_Protocol_not_set_case {
		if err := legacyOneof(legacyRawValue(raw, "protocol"), []string{
			"http", "socks5", "yuubinsya", "mix", "socks4A", "tproxy", "redir", "tun", "reverseHttp", "reverseTcp", "none",
		}, x.setProtocolOneof); err != nil {
			return err
		}
	}
	if x.WhichProtocol() == Inbound_Protocol_not_set_case {
		if err := legacyDirectOneof(raw, []string{
			"http", "socks5", "yuubinsya", "mix", "mixed", "socks4A", "socks4a", "tproxy", "redir", "tun",
			"reverseHttp", "reverse_http", "reverseTcp", "reverse_tcp", "none",
		}, x.setProtocolOneof); err != nil {
			return err
		}
	}
	return nil
}

func (x *Inbound) setNetworkOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "empty":
		x.Empty = &Empty{}
		if err := json.Unmarshal(data, x.Empty); err != nil {
			return fmt.Errorf("empty: %w", err)
		}
	case "tcpudp":
		x.Tcpudp = &Tcpudp{}
		if err := json.Unmarshal(data, x.Tcpudp); err != nil {
			return fmt.Errorf("tcpudp: %w", err)
		}
	case "quic":
		x.Quic = &Quic{}
		if err := json.Unmarshal(data, x.Quic); err != nil {
			return fmt.Errorf("quic: %w", err)
		}
	}
	return nil
}

func (x *Inbound) setProtocolOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "http":
		x.Http = &Http{}
		if err := json.Unmarshal(data, x.Http); err != nil {
			return fmt.Errorf("http: %w", err)
		}
	case "socks5":
		x.Socks5 = &Socks5{}
		if err := json.Unmarshal(data, x.Socks5); err != nil {
			return fmt.Errorf("socks5: %w", err)
		}
	case "yuubinsya":
		x.Yuubinsya = &Yuubinsya{}
		if err := json.Unmarshal(data, x.Yuubinsya); err != nil {
			return fmt.Errorf("yuubinsya: %w", err)
		}
	case "mix":
		x.Mix = &Mixed{}
		if err := json.Unmarshal(data, x.Mix); err != nil {
			return fmt.Errorf("mix: %w", err)
		}
	case "mixed":
		x.Mix = &Mixed{}
		if err := json.Unmarshal(data, x.Mix); err != nil {
			return fmt.Errorf("mixed: %w", err)
		}
	case "socks4a":
		x.Socks4A = &Socks4A{}
		if err := json.Unmarshal(data, x.Socks4A); err != nil {
			return fmt.Errorf("socks4A: %w", err)
		}
	case "tproxy":
		x.Tproxy = &Tproxy{}
		if err := json.Unmarshal(data, x.Tproxy); err != nil {
			return fmt.Errorf("tproxy: %w", err)
		}
	case "redir":
		x.Redir = &Redir{}
		if err := json.Unmarshal(data, x.Redir); err != nil {
			return fmt.Errorf("redir: %w", err)
		}
	case "tun":
		x.Tun = &Tun{}
		if err := json.Unmarshal(data, x.Tun); err != nil {
			return fmt.Errorf("tun: %w", err)
		}
	case "reversehttp":
		x.ReverseHttp = &ReverseHttp{}
		if err := json.Unmarshal(data, x.ReverseHttp); err != nil {
			return fmt.Errorf("reverseHttp: %w", err)
		}
	case "reversetcp":
		x.ReverseTcp = &ReverseTcp{}
		if err := json.Unmarshal(data, x.ReverseTcp); err != nil {
			return fmt.Errorf("reverseTcp: %w", err)
		}
	case "none":
		x.None = &Empty{}
		if err := json.Unmarshal(data, x.None); err != nil {
			return fmt.Errorf("none: %w", err)
		}
	}
	return nil
}

func (x *Transport) UnmarshalJSON(data []byte) error {
	type transportAlias Transport
	var alias transportAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*x = Transport(alias)

	if x.WhichTransport() != Transport_Transport_not_set_case {
		return nil
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if err := legacyOneof(legacyRawValue(raw, "transport"), []string{
		"normal", "tls", "mux", "http2", "websocket", "reality", "tlsAuto", "httpMock", "aead", "proxy",
	}, x.setTransportOneof); err != nil {
		return err
	}
	if x.WhichTransport() == Transport_Transport_not_set_case {
		return legacyDirectOneof(raw, []string{
			"normal", "tls", "mux", "http2", "websocket", "reality", "tlsAuto", "tls_auto", "httpMock", "http_mock", "aead", "proxy",
		}, x.setTransportOneof)
	}
	return nil
}

func (x *Transport) setTransportOneof(name string, data jsontext.Value) error {
	switch normalizedOneofCase(name) {
	case "normal":
		x.Normal = &Normal{}
		if err := json.Unmarshal(data, x.Normal); err != nil {
			return fmt.Errorf("normal: %w", err)
		}
	case "tls":
		x.Tls = &Tls{}
		if err := json.Unmarshal(data, x.Tls); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	case "mux":
		x.Mux = &Mux{}
		if err := json.Unmarshal(data, x.Mux); err != nil {
			return fmt.Errorf("mux: %w", err)
		}
	case "http2":
		x.Http2 = &Http2{}
		if err := json.Unmarshal(data, x.Http2); err != nil {
			return fmt.Errorf("http2: %w", err)
		}
	case "websocket":
		x.Websocket = &Websocket{}
		if err := json.Unmarshal(data, x.Websocket); err != nil {
			return fmt.Errorf("websocket: %w", err)
		}
	case "reality":
		x.Reality = &Reality{}
		if err := json.Unmarshal(data, x.Reality); err != nil {
			return fmt.Errorf("reality: %w", err)
		}
	case "tlsauto":
		x.TlsAuto = &TlsAuto{}
		if err := json.Unmarshal(data, x.TlsAuto); err != nil {
			return fmt.Errorf("tlsAuto: %w", err)
		}
	case "httpmock":
		x.HttpMock = &HttpMock{}
		if err := json.Unmarshal(data, x.HttpMock); err != nil {
			return fmt.Errorf("httpMock: %w", err)
		}
	case "aead":
		x.Aead = &Aead{}
		if err := json.Unmarshal(data, x.Aead); err != nil {
			return fmt.Errorf("aead: %w", err)
		}
	case "proxy":
		x.Proxy = &Proxy{}
		if err := json.Unmarshal(data, x.Proxy); err != nil {
			return fmt.Errorf("proxy: %w", err)
		}
	}
	return nil
}

func legacyOneof(data jsontext.Value, names []string, set func(string, jsontext.Value) error) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}

	var wrapped struct {
		Case  string         `json:"case"`
		Value jsontext.Value `json:"value"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Case != "" {
		if len(wrapped.Value) == 0 {
			wrapped.Value = jsontext.Value("{}")
		}
		return set(wrapped.Case, wrapped.Value)
	}

	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, name := range names {
		if v := legacyRawValue(raw, name); len(v) != 0 {
			return set(name, v)
		}
	}
	return nil
}

func legacyDirectOneof(raw map[string]jsontext.Value, names []string, set func(string, jsontext.Value) error) error {
	for _, name := range names {
		if v := legacyRawValue(raw, name); len(v) != 0 {
			return set(name, v)
		}
	}
	return nil
}

func normalizedOneofCase(name string) string {
	name = strings.ReplaceAll(name, "_", "")
	name = strings.ReplaceAll(name, "-", "")
	return strings.ToLower(name)
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
	if s == "" {
		return 0, nil
	}
	if v, ok := values[s]; ok {
		return v, nil
	}
	parsed, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unknown enum value %q", s)
	}
	return int32(parsed), nil
}

func legacyUint64(raw map[string]jsontext.Value, names ...string) (uint64, error) {
	v := legacyRawValue(raw, names...)
	if len(v) == 0 || string(v) == "null" {
		return 0, nil
	}

	var n uint64
	if err := json.Unmarshal(v, &n); err == nil {
		return n, nil
	}

	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return 0, err
	}
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func legacyRawValue(raw map[string]jsontext.Value, names ...string) jsontext.Value {
	for _, name := range names {
		if v, ok := raw[name]; ok {
			return v
		}
	}
	return nil
}
