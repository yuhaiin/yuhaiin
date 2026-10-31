package inbound

import (
	"fmt"
	"reflect"
	"strings"
)

const (
	NetworkEmpty  = "empty"
	NetworkTCPUDP = "tcp_udp"
	NetworkQUIC   = "quic"

	UDPEnabled  = "enabled"
	UDPTCPOnly  = "tcp_only"
	UDPUdpOnly  = "udp_only"
	UDPDisabled = "disabled"

	ProtocolHysteria2  = "hysteria2"
	ProtocolMasque     = "masque"
	ProtocolHTTP       = "http"
	ProtocolSocks5     = "socks5"
	ProtocolYuubinsya  = "yuubinsya"
	ProtocolMixed      = "mixed"
	ProtocolSocks4A    = "socks4a"
	ProtocolTProxy     = "tproxy"
	ProtocolRedir      = "redir"
	ProtocolTun        = "tun"
	ProtocolWireguard  = "wireguard"
	ProtocolSSTP       = "sstp"
	ProtocolKrunlet    = "krunlet"
	ProtocolReverseTCP = "reverse_tcp"
	ProtocolNone       = "none"

	TransportNormal    = "normal"
	TransportTLS       = "tls"
	TransportMux       = "mux"
	TransportHTTP2     = "http2"
	TransportWebSocket = "websocket"
	TransportReality   = "reality"
	TransportTLSAuto   = "tls_auto"
	TransportHTTPMock  = "http_mock"
	TransportAEAD      = "aead"
	TransportProxy     = "proxy"
)

// Authentication separates traffic credentials from management authentication.
// An absent configuration is legacy. An empty mode preserves the mixed behavior
// of configurations saved before explicit modes were introduced.
type Authentication struct {
	Mode  string   `json:"mode,omitzero"`
	Users []string `json:"users"`
}

func (a *Authentication) EffectiveMode() string {
	if a == nil {
		return "legacy"
	}
	if a.Mode == "" {
		return "mixed"
	}
	return a.Mode
}

type Inbound struct {
	Authentication *Authentication `json:"authentication,omitzero"`
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Enabled        bool            `json:"enabled"`
	Network        Network         `json:"network"`
	Transports     []Transport     `json:"transports"`
	Protocol       Protocol        `json:"protocol"`
}

type Capabilities struct {
	Platform  string   `json:"platform"`
	Protocols []string `json:"protocols"`
}

type Network struct {
	Type   string         `json:"type"`
	Empty  *EmptyNetwork  `json:"empty,omitzero"`
	TCPUDP *TCPUDPNetwork `json:"tcp_udp,omitzero"`
	QUIC   *QUICNetwork   `json:"quic,omitzero"`
}

type NetworkVariant interface{ NetworkType() string }

type EmptyNetwork struct{}

func (EmptyNetwork) NetworkType() string { return NetworkEmpty }

type TCPUDPNetwork struct {
	Host string `json:"host"`
	UDP  string `json:"udp"`
}

func (TCPUDPNetwork) NetworkType() string { return NetworkTCPUDP }

type QUICNetwork struct {
	Host string           `json:"host"`
	TLS  *ServerTLSConfig `json:"tls,omitzero"`
}

func (QUICNetwork) NetworkType() string { return NetworkQUIC }

func NewTypedNetwork[T NetworkVariant](value T) Network {
	var network Network
	variant := typedVariantPointer(value)
	setTaggedVariant(&network, variant.Interface().(NetworkVariant).NetworkType(), variant)
	return network
}

func (n Network) Variant() (NetworkVariant, error) {
	switch n.Type {
	case NetworkEmpty:
		if n.Empty == nil {
			return nil, fmt.Errorf("network %s missing %s field", n.Type, NetworkEmpty)
		}
		return n.Empty, nil
	case NetworkTCPUDP:
		if n.TCPUDP == nil {
			return nil, fmt.Errorf("network %s missing %s field", n.Type, NetworkTCPUDP)
		}
		return n.TCPUDP, nil
	case NetworkQUIC:
		if n.QUIC == nil {
			return nil, fmt.Errorf("network %s missing %s field", n.Type, NetworkQUIC)
		}
		return n.QUIC, nil
	default:
		return nil, fmt.Errorf("unknown network type %q", n.Type)
	}
}

func (n Network) Validate() error {
	if _, err := n.Variant(); err != nil {
		return err
	}
	if n.nonNilCount() != 1 {
		return fmt.Errorf("network %s must have exactly one concrete field", n.Type)
	}
	return nil
}

func (n Network) nonNilCount() int {
	count := 0
	if n.Empty != nil {
		count++
	}
	if n.TCPUDP != nil {
		count++
	}
	if n.QUIC != nil {
		count++
	}
	return count
}

type Protocol struct {
	Type       string              `json:"type"`
	Hysteria2  *Hysteria2Protocol  `json:"hysteria2,omitzero"`
	Masque     *MasqueProtocol     `json:"masque,omitzero"`
	HTTP       *HTTPProtocol       `json:"http,omitzero"`
	Socks5     *Socks5Protocol     `json:"socks5,omitzero"`
	Yuubinsya  *YuubinsyaProtocol  `json:"yuubinsya,omitzero"`
	Mixed      *MixedProtocol      `json:"mixed,omitzero"`
	Socks4A    *Socks4AProtocol    `json:"socks4a,omitzero"`
	TProxy     *TProxyProtocol     `json:"tproxy,omitzero"`
	Redir      *RedirProtocol      `json:"redir,omitzero"`
	Tun        *TunProtocol        `json:"tun,omitzero"`
	Wireguard  *WireguardProtocol  `json:"wireguard,omitzero"`
	SSTP       *SSTPProtocol       `json:"sstp,omitzero"`
	Krunlet    *KrunletProtocol    `json:"krunlet,omitzero"`
	ReverseTCP *ReverseTCPProtocol `json:"reverse_tcp,omitzero"`
	None       *NoneProtocol       `json:"none,omitzero"`
}

type ProtocolVariant interface{ ProtocolType() string }

// Hysteria2Protocol bandwidth values use bytes per second, from the server's perspective.
type Hysteria2Protocol struct {
	Auth                  string `json:"auth" secret:"true"`
	UploadBPS             uint64 `json:"uploadBps,omitzero"`
	DownloadBPS           uint64 `json:"downloadBps,omitzero"`
	IgnoreClientBandwidth bool   `json:"ignoreClientBandwidth,omitzero"`
	DisableUDP            bool   `json:"disableUdp,omitzero"`
	SalamanderPassword    string `json:"salamanderPassword,omitzero" secret:"true"`
	// HopPorts is a comma-separated port list/range redirected to the listener.
	// Automatic redirection requires Linux nftables and CAP_NET_ADMIN.
	HopPorts string `json:"hopPorts,omitzero"`
}

func (Hysteria2Protocol) ProtocolType() string { return ProtocolHysteria2 }

// MasqueProtocol serves RFC 9484 CONNECT-IP over HTTP/3.
// Every authenticated tunnel receives an isolated in-memory TCP/IP stack.
type MasqueProtocol struct {
	Path            string   `json:"path,omitzero"`
	AuthToken       string   `json:"authToken" secret:"true"`
	ServerAddresses []string `json:"serverAddresses"`
	ClientAddresses []string `json:"clientAddresses"`
	MTU             int      `json:"mtu,omitzero"`
	MaxSessions     int      `json:"maxSessions,omitzero"`
}

func (MasqueProtocol) ProtocolType() string { return ProtocolMasque }

type HTTPProtocol struct {
	Username string `json:"username"`
	Password string `json:"password" secret:"true"`
}

func (HTTPProtocol) ProtocolType() string { return ProtocolHTTP }

type Socks5Protocol struct {
	Username string `json:"username"`
	Password string `json:"password" secret:"true"`
	UDP      bool   `json:"udp"`
}

func (Socks5Protocol) ProtocolType() string { return ProtocolSocks5 }

type YuubinsyaProtocol struct {
	Password    string `json:"password" secret:"true"`
	UDPCoalesce bool   `json:"udpCoalesce"`
}

func (YuubinsyaProtocol) ProtocolType() string { return ProtocolYuubinsya }

type MixedProtocol struct {
	Username string `json:"username"`
	Password string `json:"password" secret:"true"`
}

func (MixedProtocol) ProtocolType() string { return ProtocolMixed }

type Socks4AProtocol struct {
	Username string `json:"username"`
}

func (Socks4AProtocol) ProtocolType() string { return ProtocolSocks4A }

type TProxyProtocol struct {
	Host         string `json:"host"`
	DNSHijacking bool   `json:"dnsHijacking"`
	ForceFakeIP  bool   `json:"forceFakeIp"`
}

func (TProxyProtocol) ProtocolType() string { return ProtocolTProxy }

type RedirProtocol struct {
	Host string `json:"host"`
}

func (RedirProtocol) ProtocolType() string { return ProtocolRedir }

type TunProtocol struct {
	OutputScheduler   string           `json:"outputScheduler,omitzero"`
	Darwin            DarwinTunOptions `json:"darwin,omitzero"`
	Stack             string           `json:"stack,omitzero"`
	CongestionControl string           `json:"congestionControl,omitzero"`
	AutoFakeIPRoute   bool             `json:"autoFakeIpRoute"`
	Name              string           `json:"name"`
	MTU               int32            `json:"mtu"`
	ForceFakeIP       bool             `json:"forceFakeIp"`
	SkipMulticast     bool             `json:"skipMulticast"`
	Driver            string           `json:"driver"`
	Portal            string           `json:"portal"`
	PortalV6          string           `json:"portalV6"`
	Routes            []string         `json:"routes"`
	Excludes          []string         `json:"excludes"`
	PostUp            []string         `json:"postUp" secret:"true" privilege:"system:execute"`
	PostDown          []string         `json:"postDown" secret:"true" privilege:"system:execute"`
}

type DarwinTunOptions struct {
	ExperimentalBatch bool `json:"experimentalBatch"`
	BatchSize         int  `json:"batchSize,omitzero"`
	PendingPackets    int  `json:"pendingPackets,omitzero"`
}

func (TunProtocol) ProtocolType() string { return ProtocolTun }

// WireguardProtocol accepts standard WireGuard peers without creating a TUN
// device or changing any host routes. Each client must have a unique host IP.
type WireguardProtocol struct {
	PrivateKey string          `json:"privateKey" secret:"true"`
	ListenPort int             `json:"listenPort"`
	Addresses  []string        `json:"addresses"`
	MTU        int             `json:"mtu,omitzero"`
	Peers      []WireguardPeer `json:"peers"`
}

type WireguardPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitzero"`
	AllowedIPs   []string `json:"allowedIps"`
}

func (WireguardProtocol) ProtocolType() string { return ProtocolWireguard }

// SSTPProtocol terminates PPP connections with isolated in-memory IP stacks.
// User access is managed through the inbound's Authentication field.
type SSTPProtocol struct {
	TLS             *ServerTLSConfig `json:"tls"`
	ServerAddress   string           `json:"serverAddress"`
	ClientAddresses []string         `json:"clientAddresses"`
	DNS             string           `json:"dns,omitzero"`
	MTU             int              `json:"mtu,omitzero"`
	MaxSessions     int              `json:"maxSessions,omitzero"`
}

func (SSTPProtocol) ProtocolType() string { return ProtocolSSTP }

// KrunletProtocol listens for native Krunlet virtual NIC flows on a local
// Unix socket. It feeds TCP/UDP directly to yuhaiin's normal inbound handler.
type KrunletProtocol struct {
	Socket string `json:"socket"`
}

func (KrunletProtocol) ProtocolType() string { return ProtocolKrunlet }

type ReverseTCPProtocol struct {
	Target string `json:"target"`
}

func (ReverseTCPProtocol) ProtocolType() string { return ProtocolReverseTCP }

type NoneProtocol struct{}

func (NoneProtocol) ProtocolType() string { return ProtocolNone }

func NewTypedProtocol[T ProtocolVariant](value T) Protocol {
	var protocol Protocol
	variant := typedVariantPointer(value)
	setTaggedVariant(&protocol, variant.Interface().(ProtocolVariant).ProtocolType(), variant)
	return protocol
}

func (p Protocol) Variant() (ProtocolVariant, error) {
	switch p.Type {
	case ProtocolMasque:
		if p.Masque == nil {
			return nil, fmt.Errorf("protocol %s missing masque field", p.Type)
		}
		return p.Masque, nil
	case ProtocolHysteria2:
		if p.Hysteria2 == nil {
			return nil, fmt.Errorf("protocol %s missing hysteria2 field", p.Type)
		}
		return p.Hysteria2, nil
	case ProtocolHTTP:
		if p.HTTP == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolHTTP)
		}
		return p.HTTP, nil
	case ProtocolSocks5:
		if p.Socks5 == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolSocks5)
		}
		return p.Socks5, nil
	case ProtocolYuubinsya:
		if p.Yuubinsya == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolYuubinsya)
		}
		return p.Yuubinsya, nil
	case ProtocolMixed:
		if p.Mixed == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolMixed)
		}
		return p.Mixed, nil
	case ProtocolSocks4A:
		if p.Socks4A == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolSocks4A)
		}
		return p.Socks4A, nil
	case ProtocolTProxy:
		if p.TProxy == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolTProxy)
		}
		return p.TProxy, nil
	case ProtocolRedir:
		if p.Redir == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolRedir)
		}
		return p.Redir, nil
	case ProtocolSSTP:
		if p.SSTP == nil {
			return nil, fmt.Errorf("protocol %s missing sstp field", p.Type)
		}
		return p.SSTP, nil
	case ProtocolWireguard:
		if p.Wireguard == nil {
			return nil, fmt.Errorf("protocol %s missing wireguard field", p.Type)
		}
		return p.Wireguard, nil
	case ProtocolTun:
		if p.Tun == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolTun)
		}
		return p.Tun, nil
	case ProtocolKrunlet:
		if p.Krunlet == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolKrunlet)
		}
		return p.Krunlet, nil
	case ProtocolReverseTCP:
		if p.ReverseTCP == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolReverseTCP)
		}
		return p.ReverseTCP, nil
	case ProtocolNone:
		if p.None == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolNone)
		}
		return p.None, nil
	default:
		return nil, fmt.Errorf("unknown protocol type %q", p.Type)
	}
}

func (p Protocol) Validate() error {
	if _, err := p.Variant(); err != nil {
		return err
	}
	if p.nonNilCount() != 1 {
		return fmt.Errorf("protocol %s must have exactly one concrete field", p.Type)
	}
	return nil
}

func (p Protocol) nonNilCount() int {
	count := 0
	if p.Hysteria2 != nil {
		count++
	}
	if p.Masque != nil {
		count++
	}
	if p.HTTP != nil {
		count++
	}
	if p.Socks5 != nil {
		count++
	}
	if p.Yuubinsya != nil {
		count++
	}
	if p.Mixed != nil {
		count++
	}
	if p.Socks4A != nil {
		count++
	}
	if p.TProxy != nil {
		count++
	}
	if p.Redir != nil {
		count++
	}
	if p.Tun != nil {
		count++
	}
	if p.Wireguard != nil {
		count++
	}
	if p.SSTP != nil {
		count++
	}
	if p.Krunlet != nil {
		count++
	}
	if p.ReverseTCP != nil {
		count++
	}
	if p.None != nil {
		count++
	}
	return count
}

type Transport struct {
	Type      string              `json:"type"`
	Normal    *NormalTransport    `json:"normal,omitzero"`
	TLS       *TLSTransport       `json:"tls,omitzero"`
	Mux       *MuxTransport       `json:"mux,omitzero"`
	HTTP2     *HTTP2Transport     `json:"http2,omitzero"`
	WebSocket *WebSocketTransport `json:"websocket,omitzero"`
	Reality   *RealityTransport   `json:"reality,omitzero"`
	TLSAuto   *TLSAutoTransport   `json:"tls_auto,omitzero"`
	HTTPMock  *HTTPMockTransport  `json:"http_mock,omitzero"`
	AEAD      *AEADTransport      `json:"aead,omitzero"`
	Proxy     *ProxyTransport     `json:"proxy,omitzero"`
}

type TransportVariant interface{ TransportType() string }

type NormalTransport struct{}

func (NormalTransport) TransportType() string { return TransportNormal }

type TLSTransport struct {
	TLS *ServerTLSConfig `json:"tls,omitzero"`
}

func (TLSTransport) TransportType() string { return TransportTLS }

type MuxTransport struct{}

func (MuxTransport) TransportType() string { return TransportMux }

type HTTP2Transport struct{}

func (HTTP2Transport) TransportType() string { return TransportHTTP2 }

type WebSocketTransport struct{}

func (WebSocketTransport) TransportType() string { return TransportWebSocket }

type RealityTransport struct {
	ShortIDs    []string `json:"shortIds" secret:"true"`
	ServerNames []string `json:"serverNames"`
	Dest        string   `json:"dest"`
	PrivateKey  string   `json:"privateKey" secret:"true"`
	PublicKey   string   `json:"publicKey"`
	MLDSA65Seed string   `json:"mldsa65Seed" secret:"true"`
	Debug       bool     `json:"debug"`
}

func (RealityTransport) TransportType() string { return TransportReality }

type TLSAutoTransport struct {
	ServerNames  []string   `json:"serverNames"`
	NextProtos   []string   `json:"nextProtos"`
	CACertBase64 []byte     `json:"caCertBase64"`
	CAKeyBase64  []byte     `json:"caKeyBase64" secret:"true"`
	ECH          *ECHConfig `json:"ech,omitzero"`
}

func (TLSAutoTransport) TransportType() string { return TransportTLSAuto }

type ECHConfig struct {
	Enabled          bool   `json:"enabled"`
	ConfigBase64     []byte `json:"configBase64"`
	PrivateKeyBase64 []byte `json:"privateKeyBase64" secret:"true"`
	OuterSNI         string `json:"outerSni"`
}

type HTTPMockTransport struct {
	DataBase64 []byte `json:"dataBase64" secret:"true"`
}

func (HTTPMockTransport) TransportType() string { return TransportHTTPMock }

type AEADTransport struct {
	Password     string `json:"password" secret:"true"`
	CryptoMethod string `json:"cryptoMethod"`
}

func (AEADTransport) TransportType() string { return TransportAEAD }

type ProxyTransport struct{}

func (ProxyTransport) TransportType() string { return TransportProxy }

func NewTypedTransport[T TransportVariant](value T) Transport {
	var transport Transport
	variant := typedVariantPointer(value)
	setTaggedVariant(&transport, variant.Interface().(TransportVariant).TransportType(), variant)
	return transport
}

func typedVariantPointer[T any](value T) reflect.Value {
	variant := reflect.ValueOf(value)
	if !variant.IsValid() {
		panic("nil inbound variant")
	}
	if variant.Kind() == reflect.Pointer {
		if variant.IsNil() {
			variant = reflect.New(variant.Type().Elem())
		}
		return variant
	}
	pointer := reflect.New(variant.Type())
	pointer.Elem().Set(variant)
	return pointer
}

func setTaggedVariant(target any, typ string, variant reflect.Value) {
	out := reflect.ValueOf(target)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		panic("inbound tagged object target must be a non-nil pointer")
	}
	out = out.Elem()
	typeField := out.FieldByName("Type")
	if !typeField.IsValid() || !typeField.CanSet() || typeField.Kind() != reflect.String {
		panic(fmt.Sprintf("inbound tagged object %s has no settable Type field", out.Type()))
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
			panic(fmt.Sprintf("inbound tagged object field %s cannot accept %s", fieldInfo.Name, variant.Type()))
		}
		field.Set(variant)
		return
	}
	panic(fmt.Sprintf("inbound tagged object %s has no variant field for %q", out.Type(), typ))
}

func jsonTagName(tag string) string {
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	return name
}

type ServerTLSConfig struct {
	Certificates          []Certificate          `json:"certificates"`
	NextProtos            []string               `json:"nextProtos"`
	ServerNameCertificate map[string]Certificate `json:"serverNameCertificate"`
}

type Certificate struct {
	CertBase64 []byte `json:"certBase64"`
	KeyBase64  []byte `json:"keyBase64" secret:"true"`
	CertFile   string `json:"certFile" privilege:"secrets:manage"`
	KeyFile    string `json:"keyFile" privilege:"secrets:manage"`
}

func (t Transport) Variant() (TransportVariant, error) {
	switch t.Type {
	case TransportNormal:
		if t.Normal == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportNormal)
		}
		return t.Normal, nil
	case TransportTLS:
		if t.TLS == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportTLS)
		}
		return t.TLS, nil
	case TransportMux:
		if t.Mux == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportMux)
		}
		return t.Mux, nil
	case TransportHTTP2:
		if t.HTTP2 == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportHTTP2)
		}
		return t.HTTP2, nil
	case TransportWebSocket:
		if t.WebSocket == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportWebSocket)
		}
		return t.WebSocket, nil
	case TransportReality:
		if t.Reality == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportReality)
		}
		return t.Reality, nil
	case TransportTLSAuto:
		if t.TLSAuto == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportTLSAuto)
		}
		return t.TLSAuto, nil
	case TransportHTTPMock:
		if t.HTTPMock == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportHTTPMock)
		}
		return t.HTTPMock, nil
	case TransportAEAD:
		if t.AEAD == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportAEAD)
		}
		return t.AEAD, nil
	case TransportProxy:
		if t.Proxy == nil {
			return nil, fmt.Errorf("transport %s missing %s field", t.Type, TransportProxy)
		}
		return t.Proxy, nil
	default:
		return nil, fmt.Errorf("unknown transport type %q", t.Type)
	}
}

func (t Transport) Validate() error {
	if _, err := t.Variant(); err != nil {
		return err
	}
	if t.nonNilCount() != 1 {
		return fmt.Errorf("transport %s must have exactly one concrete field", t.Type)
	}
	return nil
}

func (t Transport) nonNilCount() int {
	count := 0
	if t.Normal != nil {
		count++
	}
	if t.TLS != nil {
		count++
	}
	if t.Mux != nil {
		count++
	}
	if t.HTTP2 != nil {
		count++
	}
	if t.WebSocket != nil {
		count++
	}
	if t.Reality != nil {
		count++
	}
	if t.TLSAuto != nil {
		count++
	}
	if t.HTTPMock != nil {
		count++
	}
	if t.AEAD != nil {
		count++
	}
	if t.Proxy != nil {
		count++
	}
	return count
}

func (i Inbound) Validate() error {
	if i.Protocol.Type == ProtocolSSTP && i.Authentication.EffectiveMode() == "legacy" {
		return fmt.Errorf("sstp inbound requires user authentication")
	}
	if i.Authentication != nil {
		switch i.Authentication.EffectiveMode() {
		case "legacy":
			if len(i.Authentication.Users) != 0 {
				return fmt.Errorf("legacy authentication cannot select users")
			}
		case "users", "mixed":
		default:
			return fmt.Errorf("invalid inbound authentication mode")
		}
		switch i.Protocol.Type {
		case ProtocolHTTP, ProtocolSocks5, ProtocolMixed, ProtocolYuubinsya, ProtocolHysteria2, ProtocolSSTP:
		default:
			return fmt.Errorf("user authentication is unsupported for protocol %q", i.Protocol.Type)
		}
		if len(i.Authentication.Users) > 1024 {
			return fmt.Errorf("too many inbound users")
		}
		for _, id := range i.Authentication.Users {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("inbound user id is empty")
			}
		}
	}
	if i.ID == "" {
		return fmt.Errorf("inbound id is empty")
	}
	if err := i.Network.Validate(); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	if err := i.Protocol.Validate(); err != nil {
		return fmt.Errorf("protocol: %w", err)
	}
	for index, transport := range i.Transports {
		if err := transport.Validate(); err != nil {
			return fmt.Errorf("transport[%d]: %w", index, err)
		}
	}
	return nil
}
