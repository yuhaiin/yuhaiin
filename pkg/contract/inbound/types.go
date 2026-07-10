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

	ProtocolHTTP        = "http"
	ProtocolSocks5      = "socks5"
	ProtocolYuubinsya   = "yuubinsya"
	ProtocolMixed       = "mixed"
	ProtocolSocks4A     = "socks4a"
	ProtocolTProxy      = "tproxy"
	ProtocolRedir       = "redir"
	ProtocolTun         = "tun"
	ProtocolReverseHTTP = "reverse_http"
	ProtocolReverseTCP  = "reverse_tcp"
	ProtocolNone        = "none"

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

type Inbound struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Enabled    bool        `json:"enabled"`
	Network    Network     `json:"network"`
	Transports []Transport `json:"transports"`
	Protocol   Protocol    `json:"protocol"`
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
	Type        string               `json:"type"`
	HTTP        *HTTPProtocol        `json:"http,omitzero"`
	Socks5      *Socks5Protocol      `json:"socks5,omitzero"`
	Yuubinsya   *YuubinsyaProtocol   `json:"yuubinsya,omitzero"`
	Mixed       *MixedProtocol       `json:"mixed,omitzero"`
	Socks4A     *Socks4AProtocol     `json:"socks4a,omitzero"`
	TProxy      *TProxyProtocol      `json:"tproxy,omitzero"`
	Redir       *RedirProtocol       `json:"redir,omitzero"`
	Tun         *TunProtocol         `json:"tun,omitzero"`
	ReverseHTTP *ReverseHTTPProtocol `json:"reverse_http,omitzero"`
	ReverseTCP  *ReverseTCPProtocol  `json:"reverse_tcp,omitzero"`
	None        *NoneProtocol        `json:"none,omitzero"`
}

type ProtocolVariant interface{ ProtocolType() string }

type HTTPProtocol struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (HTTPProtocol) ProtocolType() string { return ProtocolHTTP }

type Socks5Protocol struct {
	Username string `json:"username"`
	Password string `json:"password"`
	UDP      bool   `json:"udp"`
}

func (Socks5Protocol) ProtocolType() string { return ProtocolSocks5 }

type YuubinsyaProtocol struct {
	Password    string `json:"password"`
	UDPCoalesce bool   `json:"udpCoalesce"`
}

func (YuubinsyaProtocol) ProtocolType() string { return ProtocolYuubinsya }

type MixedProtocol struct {
	Username string `json:"username"`
	Password string `json:"password"`
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
	Name          string   `json:"name"`
	MTU           int32    `json:"mtu"`
	ForceFakeIP   bool     `json:"forceFakeIp"`
	SkipMulticast bool     `json:"skipMulticast"`
	Driver        string   `json:"driver"`
	Portal        string   `json:"portal"`
	PortalV6      string   `json:"portalV6"`
	Routes        []string `json:"routes"`
	Excludes      []string `json:"excludes"`
	PostUp        []string `json:"postUp"`
	PostDown      []string `json:"postDown"`
}

func (TunProtocol) ProtocolType() string { return ProtocolTun }

type ReverseHTTPProtocol struct {
	URL string           `json:"url"`
	TLS *ClientTLSConfig `json:"tls,omitzero"`
}

func (ReverseHTTPProtocol) ProtocolType() string { return ProtocolReverseHTTP }

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
	case ProtocolTun:
		if p.Tun == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolTun)
		}
		return p.Tun, nil
	case ProtocolReverseHTTP:
		if p.ReverseHTTP == nil {
			return nil, fmt.Errorf("protocol %s missing %s field", p.Type, ProtocolReverseHTTP)
		}
		return p.ReverseHTTP, nil
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
	if p.ReverseHTTP != nil {
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
	ShortIDs    []string `json:"shortIds"`
	ServerNames []string `json:"serverNames"`
	Dest        string   `json:"dest"`
	PrivateKey  string   `json:"privateKey"`
	PublicKey   string   `json:"publicKey"`
	MLDSA65Seed string   `json:"mldsa65Seed"`
	Debug       bool     `json:"debug"`
}

func (RealityTransport) TransportType() string { return TransportReality }

type TLSAutoTransport struct {
	ServerNames  []string   `json:"serverNames"`
	NextProtos   []string   `json:"nextProtos"`
	CACertBase64 []byte     `json:"caCertBase64"`
	CAKeyBase64  []byte     `json:"caKeyBase64"`
	ECH          *ECHConfig `json:"ech,omitzero"`
}

func (TLSAutoTransport) TransportType() string { return TransportTLSAuto }

type ECHConfig struct {
	Enabled          bool   `json:"enabled"`
	ConfigBase64     []byte `json:"configBase64"`
	PrivateKeyBase64 []byte `json:"privateKeyBase64"`
	OuterSNI         string `json:"outerSni"`
}

type HTTPMockTransport struct {
	DataBase64 []byte `json:"dataBase64"`
}

func (HTTPMockTransport) TransportType() string { return TransportHTTPMock }

type AEADTransport struct {
	Password     string `json:"password"`
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

type ClientTLSConfig struct {
	Enabled            bool     `json:"enabled"`
	ServerNames        []string `json:"serverNames"`
	CACertsBase64      [][]byte `json:"caCertsBase64"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	NextProtos         []string `json:"nextProtos"`
	ECHConfigBase64    []byte   `json:"echConfigBase64"`
}

type ServerTLSConfig struct {
	Certificates          []Certificate          `json:"certificates"`
	NextProtos            []string               `json:"nextProtos"`
	ServerNameCertificate map[string]Certificate `json:"serverNameCertificate"`
}

type Certificate struct {
	CertBase64 []byte `json:"certBase64"`
	KeyBase64  []byte `json:"keyBase64"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
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
