package statistic

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

func (x *Type) UnmarshalJSON(data []byte) error {
	v, err := legacyEnum(data, Type_value)
	if err != nil {
		return err
	}
	*x = Type(v)
	return nil
}

func (x *NetType) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if v := legacyRawValue(raw, "conn_type", "connType"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.ConnType); err != nil {
			return fmt.Errorf("conn_type: %w", err)
		}
	}
	if v := legacyRawValue(raw, "underlying_type", "underlyingType"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.UnderlyingType); err != nil {
			return fmt.Errorf("underlying_type: %w", err)
		}
	}
	return nil
}

func (x *Connection) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var err error
	x.Addr, err = legacyString(raw, "addr")
	if err != nil {
		return fmt.Errorf("addr: %w", err)
	}
	x.Id, err = legacyUint64(raw, "id")
	if err != nil {
		return fmt.Errorf("id: %w", err)
	}
	if v := legacyRawValue(raw, "type"); len(v) != 0 && string(v) != "null" {
		x.Type = &NetType{}
		if err := json.Unmarshal(v, x.Type); err != nil {
			return fmt.Errorf("type: %w", err)
		}
	}
	x.Source, err = legacyString(raw, "source")
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	x.Inbound, err = legacyString(raw, "inbound")
	if err != nil {
		return fmt.Errorf("inbound: %w", err)
	}
	x.InboundName, err = legacyString(raw, "inbound_name", "inboundName")
	if err != nil {
		return fmt.Errorf("inbound_name: %w", err)
	}
	x.Interface, err = legacyString(raw, "interface")
	if err != nil {
		return fmt.Errorf("interface: %w", err)
	}
	x.Outbound, err = legacyString(raw, "outbound")
	if err != nil {
		return fmt.Errorf("outbound: %w", err)
	}
	x.LocalAddr, err = legacyString(raw, "LocalAddr", "local_addr", "localAddr")
	if err != nil {
		return fmt.Errorf("LocalAddr: %w", err)
	}
	x.Destionation, err = legacyString(raw, "destionation")
	if err != nil {
		return fmt.Errorf("destionation: %w", err)
	}
	x.FakeIp, err = legacyString(raw, "fake_ip", "fakeIp")
	if err != nil {
		return fmt.Errorf("fake_ip: %w", err)
	}
	x.Hosts, err = legacyString(raw, "hosts")
	if err != nil {
		return fmt.Errorf("hosts: %w", err)
	}
	x.Domain, err = legacyString(raw, "domain")
	if err != nil {
		return fmt.Errorf("domain: %w", err)
	}
	x.Ip, err = legacyString(raw, "ip")
	if err != nil {
		return fmt.Errorf("ip: %w", err)
	}
	x.Tag, err = legacyString(raw, "tag")
	if err != nil {
		return fmt.Errorf("tag: %w", err)
	}
	x.Hash, err = legacyString(raw, "hash")
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	x.NodeName, err = legacyString(raw, "node_name", "nodeName")
	if err != nil {
		return fmt.Errorf("node_name: %w", err)
	}
	x.Protocol, err = legacyString(raw, "protocol")
	if err != nil {
		return fmt.Errorf("protocol: %w", err)
	}
	x.Process, err = legacyString(raw, "process")
	if err != nil {
		return fmt.Errorf("process: %w", err)
	}
	x.Pid, err = legacyUint64(raw, "pid")
	if err != nil {
		return fmt.Errorf("pid: %w", err)
	}
	x.Uid, err = legacyUint64(raw, "uid")
	if err != nil {
		return fmt.Errorf("uid: %w", err)
	}
	x.TlsServerName, err = legacyString(raw, "tls_server_name", "tlsServerName")
	if err != nil {
		return fmt.Errorf("tls_server_name: %w", err)
	}
	x.HttpHost, err = legacyString(raw, "http_host", "httpHost")
	if err != nil {
		return fmt.Errorf("http_host: %w", err)
	}
	x.Component, err = legacyString(raw, "component")
	if err != nil {
		return fmt.Errorf("component: %w", err)
	}
	x.UdpMigrateId, err = legacyUint64(raw, "udp_migrate_id", "udpMigrateId")
	if err != nil {
		return fmt.Errorf("udp_migrate_id: %w", err)
	}
	if v := legacyRawValue(raw, "mode"); len(v) != 0 && string(v) != "null" {
		mode := config.Mode(0)
		if err := json.Unmarshal(v, &mode); err != nil {
			return fmt.Errorf("mode: %w", err)
		}
		x.Mode = &mode
	}
	if v := legacyRawValue(raw, "match_history", "matchHistory"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.MatchHistory); err != nil {
			return fmt.Errorf("match_history: %w", err)
		}
	}
	x.Resolver, err = legacyString(raw, "resolver")
	if err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	x.Geo, err = legacyString(raw, "geo")
	if err != nil {
		return fmt.Errorf("geo: %w", err)
	}
	x.OutboundGeo, err = legacyString(raw, "outbound_geo", "outboundGeo")
	if err != nil {
		return fmt.Errorf("outbound_geo: %w", err)
	}
	if v := legacyRawValue(raw, "lists"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.Lists); err != nil {
			return fmt.Errorf("lists: %w", err)
		}
	}
	return nil
}

func (x *MatchResult) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	x.ListName, err = legacyString(raw, "list_name", "listName")
	if err != nil {
		return fmt.Errorf("list_name: %w", err)
	}
	if v := legacyRawValue(raw, "matched"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.Matched); err != nil {
			return fmt.Errorf("matched: %w", err)
		}
	}
	return nil
}

func (x *MatchHistoryEntry) UnmarshalJSON(data []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	x.RuleName, err = legacyString(raw, "rule_name", "ruleName")
	if err != nil {
		return fmt.Errorf("rule_name: %w", err)
	}
	if v := legacyRawValue(raw, "history"); len(v) != 0 && string(v) != "null" {
		if err := json.Unmarshal(v, &x.History); err != nil {
			return fmt.Errorf("history: %w", err)
		}
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

func legacyRawValue(raw map[string]jsontext.Value, names ...string) jsontext.Value {
	for _, name := range names {
		if v, ok := raw[name]; ok {
			return v
		}
	}
	return nil
}

func legacyString(raw map[string]jsontext.Value, names ...string) (string, error) {
	v := legacyRawValue(raw, names...)
	if len(v) == 0 || string(v) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", err
	}
	return s, nil
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
	return strconv.ParseUint(s, 10, 64)
}
