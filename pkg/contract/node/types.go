package node

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type Node struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Group   string     `json:"group"`
	Origin  string     `json:"origin"`
	Enabled bool       `json:"enabled"`
	Chain   []Protocol `json:"chain"`
}

type Selection struct {
	TCP *Node `json:"tcp,omitzero"`
	UDP *Node `json:"udp,omitzero"`
}

type LatencyRequest struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	UserAgent    string `json:"userAgent"`
	Host         string `json:"host"`
	TargetDomain string `json:"targetDomain"`
	IPv6         bool   `json:"ipv6"`
	TCP          bool   `json:"tcp"`
}

type LatencyResponse struct {
	OK        bool         `json:"ok"`
	LatencyMS int64        `json:"latencyMs,omitzero"`
	IP        *IPLatency   `json:"ip,omitzero"`
	STUN      *STUNLatency `json:"stun,omitzero"`
	Error     string       `json:"error,omitzero"`
}

type IPLatency struct {
	IPv4 string `json:"ipv4,omitzero"`
	IPv6 string `json:"ipv6,omitzero"`
}

type STUNLatency struct {
	XORMappedAddress      string `json:"xorMappedAddress,omitzero"`
	MappedAddress         string `json:"mappedAddress,omitzero"`
	OtherAddress          string `json:"otherAddress,omitzero"`
	ResponseOriginAddress string `json:"responseOriginAddress,omitzero"`
	Software              string `json:"software,omitzero"`
	Mapping               string `json:"mapping,omitzero"`
	Filtering             string `json:"filtering,omitzero"`
}

type Protocol struct {
	Type string `json:"type"`

	Shadowsocks          *Shadowsocks          `json:"shadowsocks,omitzero"`
	Shadowsocksr         *Shadowsocksr         `json:"shadowsocksr,omitzero"`
	Vmess                *Vmess                `json:"vmess,omitzero"`
	Websocket            *Websocket            `json:"websocket,omitzero"`
	Quic                 *Quic                 `json:"quic,omitzero"`
	ObfsHTTP             *ObfsHTTP             `json:"obfs_http,omitzero"`
	Trojan               *Trojan               `json:"trojan,omitzero"`
	Simple               *Fixed                `json:"simple,omitzero"`
	None                 *None                 `json:"none,omitzero"`
	Socks5               *Socks5               `json:"socks5,omitzero"`
	HTTP                 *HTTP                 `json:"http,omitzero"`
	Direct               *Direct               `json:"direct,omitzero"`
	Reject               *Reject               `json:"reject,omitzero"`
	Yuubinsya            *Yuubinsya            `json:"yuubinsya,omitzero"`
	HTTP2                *Concurrency          `json:"http2,omitzero"`
	Reality              *Reality              `json:"reality,omitzero"`
	TLS                  *TLS                  `json:"tls,omitzero"`
	Wireguard            *Wireguard            `json:"wireguard,omitzero"`
	Mux                  *Concurrency          `json:"mux,omitzero"`
	Drop                 *Drop                 `json:"drop,omitzero"`
	Vless                *Vless                `json:"vless,omitzero"`
	BootstrapDNSWarp     *BootstrapDNSWarp     `json:"bootstrap_dns_warp,omitzero"`
	Tailscale            *Tailscale            `json:"tailscale,omitzero"`
	Set                  *Set                  `json:"set,omitzero"`
	TLSTermination       *TLSTermination       `json:"tls_termination,omitzero"`
	HTTPTermination      *HTTPTermination      `json:"http_termination,omitzero"`
	HTTPMock             *HTTPMock             `json:"http_mock,omitzero"`
	AEAD                 *AEAD                 `json:"aead,omitzero"`
	Fixed                *Fixed                `json:"fixed,omitzero"`
	NetworkSplit         *NetworkSplit         `json:"network_split,omitzero"`
	CloudflareWarpMasque *CloudflareWarpMasque `json:"cloudflare_warp_masque,omitzero"`
	Proxy                *Proxy                `json:"proxy,omitzero"`
	FixedV2              *FixedV2              `json:"fixedv2,omitzero"`
	PointAsEndpoint      *PointAsEndpoint      `json:"point_as_endpoint,omitzero"`
}

type None struct{}
type Reject struct{}
type Drop struct{}
type Proxy struct{}
type BootstrapDNSWarp struct{}

type Direct struct {
	NetworkInterface string `json:"network_interface,omitzero"`
}

type Shadowsocks struct {
	Method   string `json:"method"`
	Password string `json:"password"`
}

type Shadowsocksr struct {
	Server     string `json:"server"`
	Port       string `json:"port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
	Obfs       string `json:"obfs"`
	ObfsParam  string `json:"obfsparam"`
	Protocol   string `json:"protocol"`
	ProtoParam string `json:"protoparam"`
}

type Vmess struct {
	UUID     string `json:"id"`
	AlterID  string `json:"aid"`
	Security string `json:"security"`
}

type Vless struct {
	UUID string `json:"uuid"`
}

type Websocket struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type Quic struct {
	Host string `json:"host"`
	TLS  TLS    `json:"tls,omitzero"`
}

type ObfsHTTP struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type Trojan struct {
	Password string `json:"password"`
	Peer     string `json:"peer"`
}

type Fixed struct {
	Host             string         `json:"host"`
	Port             int32          `json:"port,omitzero"`
	AlternateHost    []FixedAddress `json:"alternate_host,omitzero"`
	NetworkInterface string         `json:"network_interface,omitzero"`
}

type FixedV2 struct {
	Addresses        []FixedAddress `json:"addresses,omitzero"`
	UDPHappyEyeballs bool           `json:"udp_happy_eyeballs,omitzero"`
}

type FixedAddress struct {
	Host             string `json:"host"`
	Port             int32  `json:"port,omitzero"`
	NetworkInterface string `json:"network_interface,omitzero"`
}

type Socks5 struct {
	User         string `json:"user"`
	Password     string `json:"password"`
	Hostname     string `json:"hostname"`
	OverridePort int32  `json:"override_port,omitzero"`
}

type HTTP struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type Yuubinsya struct {
	Password      string `json:"password"`
	UDPOverStream bool   `json:"udp_over_stream,omitzero"`
	UDPCoalesce   bool   `json:"udp_coalesce,omitzero"`
}

type Concurrency struct {
	Concurrency int32 `json:"concurrency,omitzero"`
}

type Reality struct {
	ServerName    string `json:"server_name"`
	PublicKey     string `json:"public_key"`
	MLDSA65Verify string `json:"mldsa65_verify,omitzero"`
	ShortID       string `json:"short_id,omitzero"`
	Debug         bool   `json:"debug,omitzero"`
}

type TLS struct {
	Enable             bool     `json:"enable"`
	ServerNames        []string `json:"servernames,omitzero"`
	CACert             [][]byte `json:"ca_cert,omitzero"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitzero"`
	NextProtos         []string `json:"next_protos,omitzero"`
	ECHConfig          []byte   `json:"ech_config,omitzero"`
}

type ServerTLS struct {
	Certificates          []Certificate          `json:"certificates,omitzero"`
	NextProtos            []string               `json:"next_protos,omitzero"`
	ServerNameCertificate map[string]Certificate `json:"serverNameCertificate,omitzero"`
}

type Certificate struct {
	Cert         []byte `json:"cert,omitzero"`
	Key          []byte `json:"key,omitzero"`
	CertFilePath string `json:"cert_file_path,omitzero"`
	KeyFilePath  string `json:"key_file_path,omitzero"`
}

type TLSTermination struct {
	TLS ServerTLS `json:"tls"`
}

type Wireguard struct {
	SecretKey string          `json:"secretKey"`
	Endpoint  []string        `json:"endpoint,omitzero"`
	Peers     []WireguardPeer `json:"peers,omitzero"`
	MTU       int32           `json:"mtu,omitzero"`
	Reserved  []byte          `json:"reserved,omitzero"`
}

type WireguardPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitzero"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    int32    `json:"keepAlive,omitzero"`
	AllowedIPs   []string `json:"allowedIps,omitzero"`
}

type Tailscale struct {
	AuthKey    string `json:"auth_key"`
	Hostname   string `json:"hostname"`
	ControlURL string `json:"control_url"`
	Debug      bool   `json:"debug,omitzero"`
}

type Set struct {
	Nodes    []string `json:"nodes,omitzero"`
	Strategy string   `json:"strategy,omitzero"`
}

type HTTPTermination struct {
	Headers map[string]HTTPHeaders `json:"headers,omitzero"`
}

type HTTPHeaders struct {
	Headers []HTTPHeader `json:"headers,omitzero"`
}

type HTTPHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type HTTPMock struct {
	Data []byte `json:"data,omitzero"`
}

type AEAD struct {
	Password     string `json:"password"`
	CryptoMethod string `json:"crypto_method"`
}

type NetworkSplit struct {
	TCP *Protocol `json:"tcp,omitzero"`
	UDP *Protocol `json:"udp,omitzero"`
}

type CloudflareWarpMasque struct {
	PrivateKey        string   `json:"private_key"`
	Endpoint          string   `json:"endpoint"`
	EndpointPublicKey string   `json:"endpoint_public_key"`
	LocalAddresses    []string `json:"local_addresses,omitzero"`
	MTU               int32    `json:"mtu,omitzero"`
}

type PointAsEndpoint struct {
	Hash string `json:"hash"`
}

type Simple Fixed
type HTTP2 Concurrency
type Mux Concurrency

type ProtocolVariant interface{ ProtocolType() string }

func (Shadowsocks) ProtocolType() string          { return "shadowsocks" }
func (Shadowsocksr) ProtocolType() string         { return "shadowsocksr" }
func (Vmess) ProtocolType() string                { return "vmess" }
func (Websocket) ProtocolType() string            { return "websocket" }
func (Quic) ProtocolType() string                 { return "quic" }
func (ObfsHTTP) ProtocolType() string             { return "obfs_http" }
func (Trojan) ProtocolType() string               { return "trojan" }
func (Simple) ProtocolType() string               { return "simple" }
func (None) ProtocolType() string                 { return "none" }
func (Socks5) ProtocolType() string               { return "socks5" }
func (HTTP) ProtocolType() string                 { return "http" }
func (Direct) ProtocolType() string               { return "direct" }
func (Reject) ProtocolType() string               { return "reject" }
func (Yuubinsya) ProtocolType() string            { return "yuubinsya" }
func (HTTP2) ProtocolType() string                { return "http2" }
func (Reality) ProtocolType() string              { return "reality" }
func (TLS) ProtocolType() string                  { return "tls" }
func (Wireguard) ProtocolType() string            { return "wireguard" }
func (Mux) ProtocolType() string                  { return "mux" }
func (Drop) ProtocolType() string                 { return "drop" }
func (Vless) ProtocolType() string                { return "vless" }
func (BootstrapDNSWarp) ProtocolType() string     { return "bootstrap_dns_warp" }
func (Tailscale) ProtocolType() string            { return "tailscale" }
func (Set) ProtocolType() string                  { return "set" }
func (TLSTermination) ProtocolType() string       { return "tls_termination" }
func (HTTPTermination) ProtocolType() string      { return "http_termination" }
func (HTTPMock) ProtocolType() string             { return "http_mock" }
func (AEAD) ProtocolType() string                 { return "aead" }
func (Fixed) ProtocolType() string                { return "fixed" }
func (NetworkSplit) ProtocolType() string         { return "network_split" }
func (CloudflareWarpMasque) ProtocolType() string { return "cloudflare_warp_masque" }
func (Proxy) ProtocolType() string                { return "proxy" }
func (FixedV2) ProtocolType() string              { return "fixedv2" }
func (PointAsEndpoint) ProtocolType() string      { return "point_as_endpoint" }

type ProtocolPayload interface {
	ProtocolVariant
}

func NewTypedProtocol[T ProtocolPayload](value T) (Protocol, error) {
	switch v := any(value).(type) {
	case Simple:
		return newTaggedProtocol("simple", Fixed(v))
	case *Simple:
		if v == nil {
			return newTaggedProtocol("simple", Fixed{})
		}
		return newTaggedProtocol("simple", Fixed(*v))
	case HTTP2:
		return newTaggedProtocol("http2", Concurrency(v))
	case *HTTP2:
		if v == nil {
			return newTaggedProtocol("http2", Concurrency{})
		}
		return newTaggedProtocol("http2", Concurrency(*v))
	case Mux:
		return newTaggedProtocol("mux", Concurrency(v))
	case *Mux:
		if v == nil {
			return newTaggedProtocol("mux", Concurrency{})
		}
		return newTaggedProtocol("mux", Concurrency(*v))
	}

	variant, err := typedProtocolVariantPointer(value)
	if err != nil {
		return Protocol{}, err
	}
	return newProtocolFromReflectValue(variant.Interface().(ProtocolVariant).ProtocolType(), variant)
}

func newTaggedProtocol[T any](typ string, value T) (Protocol, error) {
	variant, err := typedProtocolVariantPointer(value)
	if err != nil {
		return Protocol{}, err
	}
	return newProtocolFromReflectValue(typ, variant)
}

func typedProtocolVariantPointer[T any](value T) (reflect.Value, error) {
	variant := reflect.ValueOf(value)
	if !variant.IsValid() {
		return reflect.Value{}, errors.New("node protocol variant is nil")
	}
	if variant.Kind() == reflect.Pointer {
		if variant.IsNil() {
			variant = reflect.New(variant.Type().Elem())
		}
		return variant, nil
	}
	pointer := reflect.New(variant.Type())
	pointer.Elem().Set(variant)
	return pointer, nil
}

func newProtocolFromReflectValue(typ string, variant reflect.Value) (Protocol, error) {
	var protocol Protocol
	if err := setTaggedProtocolVariant(&protocol, typ, variant); err != nil {
		return Protocol{}, err
	}
	return protocol, nil
}

func setTaggedProtocolVariant(protocol *Protocol, typ string, variant reflect.Value) error {
	out := reflect.ValueOf(protocol)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		return errors.New("node protocol target must be a non-nil pointer")
	}
	out = out.Elem()
	typeField := out.FieldByName("Type")
	if !typeField.IsValid() || !typeField.CanSet() || typeField.Kind() != reflect.String {
		return fmt.Errorf("node protocol %s has no settable Type field", out.Type())
	}
	typeField.SetString(typ)

	outType := out.Type()
	for i := 0; i < out.NumField(); i++ {
		fieldInfo := outType.Field(i)
		if jsonTagName(fieldInfo.Tag.Get("json")) != typ {
			continue
		}
		field := out.Field(i)
		if !field.CanSet() || !variant.Type().AssignableTo(field.Type()) {
			return fmt.Errorf("node protocol field %s cannot accept %s", fieldInfo.Name, variant.Type())
		}
		field.Set(variant)
		return nil
	}
	return fmt.Errorf("node protocol has no variant field for %q", typ)
}

func jsonTagName(tag string) string {
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	return name
}

func (x Node) Validate() error {
	if strings.TrimSpace(x.ID) == "" {
		return errors.New("node id is empty")
	}
	if strings.TrimSpace(x.Name) == "" {
		return errors.New("node name is empty")
	}
	if x.Origin == "" {
		return errors.New("node origin is empty")
	}
	if len(x.Chain) == 0 {
		return errors.New("node chain is empty")
	}
	for i, protocol := range x.Chain {
		if err := protocol.Validate(); err != nil {
			return fmt.Errorf("node chain[%d]: %w", i, err)
		}
	}
	return nil
}

func (x Protocol) Validate() error {
	if strings.TrimSpace(x.Type) == "" {
		return errors.New("protocol type is empty")
	}
	var count int
	var active string
	for name, ok := range x.presentVariants() {
		if !ok {
			continue
		}
		count++
		active = name
	}
	if count == 0 {
		return fmt.Errorf("protocol %q has no concrete object", x.Type)
	}
	if count > 1 {
		return fmt.Errorf("protocol %q has multiple concrete objects", x.Type)
	}
	if active != x.Type {
		return fmt.Errorf("protocol type %q does not match concrete object %q", x.Type, active)
	}
	return nil
}

func (x Protocol) presentVariants() map[string]bool {
	return map[string]bool{
		"shadowsocks":            x.Shadowsocks != nil,
		"shadowsocksr":           x.Shadowsocksr != nil,
		"vmess":                  x.Vmess != nil,
		"websocket":              x.Websocket != nil,
		"quic":                   x.Quic != nil,
		"obfs_http":              x.ObfsHTTP != nil,
		"trojan":                 x.Trojan != nil,
		"simple":                 x.Simple != nil,
		"none":                   x.None != nil,
		"socks5":                 x.Socks5 != nil,
		"http":                   x.HTTP != nil,
		"direct":                 x.Direct != nil,
		"reject":                 x.Reject != nil,
		"yuubinsya":              x.Yuubinsya != nil,
		"http2":                  x.HTTP2 != nil,
		"reality":                x.Reality != nil,
		"tls":                    x.TLS != nil,
		"wireguard":              x.Wireguard != nil,
		"mux":                    x.Mux != nil,
		"drop":                   x.Drop != nil,
		"vless":                  x.Vless != nil,
		"bootstrap_dns_warp":     x.BootstrapDNSWarp != nil,
		"tailscale":              x.Tailscale != nil,
		"set":                    x.Set != nil,
		"tls_termination":        x.TLSTermination != nil,
		"http_termination":       x.HTTPTermination != nil,
		"http_mock":              x.HTTPMock != nil,
		"aead":                   x.AEAD != nil,
		"fixed":                  x.Fixed != nil,
		"network_split":          x.NetworkSplit != nil,
		"cloudflare_warp_masque": x.CloudflareWarpMasque != nil,
		"proxy":                  x.Proxy != nil,
		"fixedv2":                x.FixedV2 != nil,
		"point_as_endpoint":      x.PointAsEndpoint != nil,
	}
}
