package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"uuid"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
)

// Share links are an import format, not a persisted model. Parse directly into
// the current contract instead of dragging the old protobuf schema into runtime.
func parseShareURL(data []byte, group, _ string) (contractnode.Node, error) {
	raw := strings.TrimSpace(string(data))
	u, err := url.Parse(raw)
	if err != nil {
		return contractnode.Node{}, errors.New("invalid share link")
	}
	switch strings.ToLower(u.Scheme) {
	case "ss":
		return parseSSLink(u, group)
	case "ssr":
		return parseSSRLink(raw, group)
	case "vmess":
		return parseVMessLink(raw, group)
	case "trojan":
		return parseTrojanLink(u, group)
	default:
		return contractnode.Node{}, errors.New("unsupported share link scheme")
	}
}

func linkNode(group, name, host string, port int32, chain ...contractnode.Protocol) (contractnode.Node, error) {
	if host == "" || port < 1 || port > 65535 {
		return contractnode.Node{}, errors.New("invalid share link endpoint")
	}
	endpoint, err := contractnode.NewTypedProtocol(contractnode.Simple{Host: host, Port: port})
	if err != nil {
		return contractnode.Node{}, err
	}
	return contractnode.Node{
		Name: name, Group: group, Origin: "remote", Enabled: true,
		Chain: append([]contractnode.Protocol{endpoint}, chain...),
	}, nil
}

func linkProtocol[T contractnode.ProtocolPayload](value T) (contractnode.Protocol, error) {
	return contractnode.NewTypedProtocol(value)
}

func parseLinkPort(text string) (int32, error) {
	n, err := strconv.ParseUint(text, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("invalid share link port")
	}
	return int32(n), nil
}

func decodeLinkBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if data, err := enc.DecodeString(s); err == nil {
			return data, nil
		}
	}
	return nil, errors.New("invalid base64 share link")
}

func parseSSLink(u *url.URL, group string) (contractnode.Node, error) {
	// Accept SIP002 userinfo as well as the older fully encoded authority.
	if u.Host == "" && u.Opaque != "" {
		decoded, err := decodeLinkBase64(strings.SplitN(u.Opaque, "#", 2)[0])
		if err != nil {
			return contractnode.Node{}, err
		}
		var parseErr error
		u, parseErr = url.Parse("ss://" + string(decoded))
		if parseErr != nil {
			return contractnode.Node{}, errors.New("invalid shadowsocks authority")
		}
	}
	port, err := parseLinkPort(u.Port())
	if err != nil {
		return contractnode.Node{}, err
	}
	if u.User == nil {
		return contractnode.Node{}, errors.New("missing shadowsocks credentials")
	}
	user := u.User.String()
	if decoded, err := decodeLinkBase64(user); err == nil {
		user = string(decoded)
	}
	method, password, ok := strings.Cut(user, ":")
	if !ok || method == "" {
		return contractnode.Node{}, errors.New("invalid shadowsocks credentials")
	}
	ss, err := linkProtocol(contractnode.Shadowsocks{Method: method, Password: password})
	if err != nil {
		return contractnode.Node{}, err
	}
	chain := []contractnode.Protocol{}
	// Shadowsocks plugins precede the encryption layer in the outbound chain.
	opts := map[string]string{}
	for option := range strings.SplitSeq(u.Query().Get("plugin"), ";") {
		key, value, present := strings.Cut(option, "=")
		if !present {
			value = "true"
		}
		opts[key] = value
	}
	switch {
	case opts["obfs-local"] == "true":
		host, proxyPort, err := net.SplitHostPort(opts["obfs-host"])
		if err != nil {
			return contractnode.Node{}, errors.New("invalid obfs host")
		}
		obfs, err := linkProtocol(contractnode.ObfsHTTP{Host: host, Port: proxyPort})
		if err != nil {
			return contractnode.Node{}, err
		}
		chain = append(chain, obfs)
	case opts["v2ray"] == "true" && opts["mode"] == "websocket":
		if opts["tls"] == "true" {
			tls, err := linkProtocol(contractnode.TLS{Enable: true, ServerNames: []string{opts["host"]}})
			if err != nil {
				return contractnode.Node{}, err
			}
			chain = append(chain, tls)
		}
		ws, err := linkProtocol(contractnode.Websocket{Host: opts["host"], Path: opts["path"]})
		if err != nil {
			return contractnode.Node{}, err
		}
		chain = append(chain, ws)
	}
	chain = append(chain, ss)
	return linkNode(group, "[ss]"+u.Fragment, u.Hostname(), port, chain...)
}

func parseTrojanLink(u *url.URL, group string) (contractnode.Node, error) {
	port, err := parseLinkPort(u.Port())
	if err != nil {
		return contractnode.Node{}, err
	}
	if u.User == nil {
		return contractnode.Node{}, errors.New("missing trojan password")
	}
	sni := u.Query().Get("sni")
	tls, err := linkProtocol(contractnode.TLS{Enable: true, ServerNames: nonEmptyStrings(sni)})
	if err != nil {
		return contractnode.Node{}, err
	}
	trojan, err := linkProtocol(contractnode.Trojan{Password: u.User.Username(), Peer: u.Query().Get("peer")})
	if err != nil {
		return contractnode.Node{}, err
	}
	return linkNode(group, "[trojan]"+u.Fragment, u.Hostname(), port, tls, trojan)
}

func nonEmptyStrings(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func parseSSRLink(raw, group string) (contractnode.Node, error) {
	encoded := strings.TrimPrefix(raw, "ssr://")
	decoded, err := decodeLinkBase64(encoded)
	if err != nil {
		return contractnode.Node{}, err
	}
	parts := bytes.SplitN(decoded, []byte("/?"), 2)
	// IPv6 literals may contain colons; split the trailing five fields.
	segments := strings.Split(string(parts[0]), ":")
	if len(segments) < 6 {
		return contractnode.Node{}, errors.New("invalid shadowsocksr link")
	}
	base := len(segments) - 5
	host := strings.Trim(strings.Join(segments[:base], ":"), "[]")
	port, err := parseLinkPort(segments[base])
	if err != nil {
		return contractnode.Node{}, err
	}
	password, err := decodeLinkBase64(segments[base+4])
	if err != nil {
		return contractnode.Node{}, err
	}
	params := url.Values{}
	if len(parts) > 1 {
		params, err = url.ParseQuery(string(parts[1]))
		if err != nil {
			return contractnode.Node{}, errors.New("invalid shadowsocksr query")
		}
	}
	decodeParam := func(key string) string {
		decoded, err := decodeLinkBase64(params.Get(key))
		if err != nil {
			return ""
		}
		return string(decoded)
	}
	protocol, err := linkProtocol(contractnode.Shadowsocksr{
		Server: host, Port: segments[base], Protocol: segments[base+1],
		Method: segments[base+2], Obfs: segments[base+3],
		Password: string(password), ObfsParam: decodeParam("obfsparam"), ProtoParam: decodeParam("protoparam"),
	})
	if err != nil {
		return contractnode.Node{}, err
	}
	return linkNode(group, "[ssr]"+decodeParam("remarks"), host, port, protocol)
}

func parseVMessLink(raw, group string) (contractnode.Node, error) {
	decoded, err := decodeLinkBase64(strings.TrimPrefix(raw, "vmess://"))
	if err != nil {
		return contractnode.Node{}, err
	}
	var params struct {
		Address string `json:"add"`
		Port json.Number `json:"port"`
		UUID string `json:"id"`
		AlterID json.Number `json:"aid"`
		Security string `json:"security"`
		Name string `json:"ps"`
		Remark string `json:"remark"`
		Network string `json:"net"`
		HeaderType string `json:"headerType"`
		Type string `json:"type"`
		TLS string `json:"tls"`
		SNI string `json:"sni"`
		Host string `json:"host"`
		Path string `json:"path"`
		VerifyCert bool `json:"verify_cert"`
	}
	// The classic vmess format allows numeric or string port/alterId.
	if err := json.Unmarshal(decoded, &params); err != nil {
		return contractnode.Node{}, errors.New("invalid vmess link JSON")
	}
	port, err := parseLinkPort(string(params.Port))
	if err != nil {
		return contractnode.Node{}, err
	}
	headerType := params.HeaderType
	if headerType == "" {
		headerType = params.Type
	}
	if headerType != "" && headerType != "none" {
		return contractnode.Node{}, errors.New("unsupported vmess header")
	}
	chain := []contractnode.Protocol{}
	if params.TLS == "tls" {
		sni := params.SNI
		if sni == "" {
			sni = params.Host
		}
		tls, err := linkProtocol(contractnode.TLS{Enable: true, ServerNames: nonEmptyStrings(sni), InsecureSkipVerify: !params.VerifyCert})
		if err != nil {
			return contractnode.Node{}, err
		}
		chain = append(chain, tls)
	}
	switch params.Network {
	case "", "tcp":
	case "ws":
		ws, err := linkProtocol(contractnode.Websocket{Host: params.Host, Path: params.Path})
		if err != nil {
			return contractnode.Node{}, err
		}
		chain = append(chain, ws)
	default:
		return contractnode.Node{}, errors.New("unsupported vmess transport")
	}
	vmess, err := linkProtocol(contractnode.Vmess{UUID: params.UUID, AlterID: string(params.AlterID), Security: params.Security})
	if err != nil {
		return contractnode.Node{}, err
	}
	chain = append(chain, vmess)
	name := params.Name
	if name == "" {
		name = params.Remark
	}
	return linkNode(group, "[vmess]"+name, params.Address, port, chain...)
}

func parseYuhaiinURL(raw string) (ParsedYuhaiinURL, error) {
	encoded := strings.TrimPrefix(raw, "yuhaiin://")
	decoded, err := decodeLinkBase64(encoded)
	if err != nil {
		return ParsedYuhaiinURL{}, err
	}
	var payload struct {
		Name string `json:"name"`
		Points *struct {
			Points []json.RawMessage `json:"points"`
		} `json:"points"`
		Remote *struct {
			Publish *contractsubscription.Publish `json:"publish"`
		} `json:"remote"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return ParsedYuhaiinURL{}, errors.New("invalid yuhaiin link JSON")
	}
	name := payload.Name
	if name == "" {
		name = "default"
	}
	result := ParsedYuhaiinURL{Name: name}
	switch {
	case payload.Remote != nil && payload.Remote.Publish != nil:
		result.Remote = payload.Remote.Publish
	case payload.Points != nil:
		for _, raw := range payload.Points.Points {
			point, err := decodeSharedPoint(raw)
			if err != nil {
				return ParsedYuhaiinURL{}, err
			}
			result.Points = append(result.Points, point)
		}
	default:
		return ParsedYuhaiinURL{}, fmt.Errorf("unknown yuhaiin link type")
	}
	return result, nil
}


func decodeSharedPoint(raw json.RawMessage) (contractnode.Node, error) {
	var current contractnode.Node
	if err := json.Unmarshal(raw, &current); err == nil && len(current.Chain) != 0 {
		if current.ID == "" {
			current.ID = uuid.New().String()
		}
		if current.Origin == "" {
			current.Origin = "remote"
		}
		if err := current.Validate(); err != nil {
			return contractnode.Node{}, err
		}
		return current, nil
	}

	// Existing yuhaiin:// URLs contain a small protobuf-shaped JSON envelope.
	// Decode only link-facing fields here; persisted protobuf migration is gone.
	var old struct {
		Hash string `json:"hash"`
		Name string `json:"name"`
		Group string `json:"group"`
		Origin int `json:"origin"`
		Protocols []map[string]json.RawMessage `json:"protocols"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		return contractnode.Node{}, errors.New("invalid shared node")
	}
	origin := "reserve"
	if old.Origin == 101 {
		origin = "remote"
	} else if old.Origin == 102 {
		origin = "manual"
	}
	point := contractnode.Node{ID: old.Hash, Name: old.Name, Group: old.Group, Origin: origin, Enabled: true}
	if point.ID == "" {
		point.ID = uuid.New().String()
	}
	for _, entry := range old.Protocols {
		if len(entry) != 1 {
			return contractnode.Node{}, errors.New("invalid shared protocol")
		}
		for name, value := range entry {
			protocol, err := decodeSharedProtocol(name, value)
			if err != nil {
				return contractnode.Node{}, err
			}
			point.Chain = append(point.Chain, protocol)
		}
	}
	if err := point.Validate(); err != nil {
		return contractnode.Node{}, err
	}
	return point, nil
}

func decodeSharedPayload[T contractnode.ProtocolPayload](data json.RawMessage) (contractnode.Protocol, error) {
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return contractnode.Protocol{}, errors.New("invalid shared protocol payload")
	}
	return contractnode.NewTypedProtocol(value)
}

func decodeSharedProtocol(name string, data json.RawMessage) (contractnode.Protocol, error) {
	switch name {
	case "simple":
		return decodeSharedPayload[contractnode.Simple](data)
	case "tls":
		return decodeSharedPayload[contractnode.TLS](data)
	case "shadowsocks":
		return decodeSharedPayload[contractnode.Shadowsocks](data)
	case "shadowsocksr":
		return decodeSharedPayload[contractnode.Shadowsocksr](data)
	case "vmess":
		return decodeSharedPayload[contractnode.Vmess](data)
	case "websocket":
		return decodeSharedPayload[contractnode.Websocket](data)
	case "quic":
		return decodeSharedPayload[contractnode.Quic](data)
	case "obfsHttp":
		return decodeSharedPayload[contractnode.ObfsHTTP](data)
	case "trojan":
		return decodeSharedPayload[contractnode.Trojan](data)
	case "none":
		return decodeSharedPayload[contractnode.None](data)
	case "socks5":
		return decodeSharedPayload[contractnode.Socks5](data)
	case "http":
		return decodeSharedPayload[contractnode.HTTP](data)
	case "direct":
		return decodeSharedPayload[contractnode.Direct](data)
	case "reject":
		return decodeSharedPayload[contractnode.Reject](data)
	case "yuubinsya":
		return decodeSharedPayload[contractnode.Yuubinsya](data)
	case "vless":
		return decodeSharedPayload[contractnode.Vless](data)
	case "wireguard":
		return decodeSharedPayload[contractnode.Wireguard](data)
	case "drop":
		return decodeSharedPayload[contractnode.Drop](data)
	case "reality":
		return decodeSharedPayload[contractnode.Reality](data)
	case "fixed", "fixedv2":
		if name == "fixed" {
			return decodeSharedPayload[contractnode.Fixed](data)
		}
		return decodeSharedPayload[contractnode.FixedV2](data)
	case "pointAsEndpoint":
		return decodeSharedPayload[contractnode.PointAsEndpoint](data)
	default:
		return contractnode.Protocol{}, fmt.Errorf("unsupported shared protocol %q", name)
	}
}
