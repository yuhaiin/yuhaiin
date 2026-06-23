package config

import (
	"github.com/Asutorufa/yuhaiin/pkg/structs/node"
)

type InboundConfig struct {
	HijackDns       bool               `json:"hijack_dns"`
	HijackDnsFakeip bool               `json:"hijack_dns_fakeip"`
	Inbounds        map[string]Inbound `json:"inbounds"`
	Sniff           Sniff              `json:"sniff"`
}

type Inbound struct {
	Name      string          `json:"name"`
	Enabled   bool            `json:"enabled"`
	Network   InboundNetwork  `json:"network"`
	Transport []Transport     `json:"transport"`
	Protocol  InboundProtocol `json:"protocol"`
}

type InboundNetworkType int32

const (
	InboundNetworkTypeEmpty  InboundNetworkType = 0
	InboundNetworkTypeTcpudp InboundNetworkType = 1
	InboundNetworkTypeQuic   InboundNetworkType = 2
)

type InboundNetwork struct {
	Type   InboundNetworkType `json:"type"`
	Empty  *Empty             `json:"empty,omitempty"`
	Tcpudp *Tcpudp            `json:"tcpudp,omitempty"`
	Quic   *Quic              `json:"quic,omitempty"`
}

type InboundProtocolType int32

const (
	InboundProtocolTypeHttp        InboundProtocolType = 0
	InboundProtocolTypeSocks5      InboundProtocolType = 1
	InboundProtocolTypeYuubinsya   InboundProtocolType = 2
	InboundProtocolTypeMixed       InboundProtocolType = 3
	InboundProtocolTypeSocks4a     InboundProtocolType = 4
	InboundProtocolTypeTproxy      InboundProtocolType = 5
	InboundProtocolTypeRedir       InboundProtocolType = 6
	InboundProtocolTypeTun         InboundProtocolType = 7
	InboundProtocolTypeReverseHttp InboundProtocolType = 8
	InboundProtocolTypeReverseTcp  InboundProtocolType = 9
	InboundProtocolTypeNone        InboundProtocolType = 10
)

type InboundProtocol struct {
	Type        InboundProtocolType `json:"type"`
	Http        *Http               `json:"http,omitempty"`
	Socks5      *Socks5             `json:"socks5,omitempty"`
	Yuubinsya   *Yuubinsya          `json:"yuubinsya,omitempty"`
	Mixed       *Mixed              `json:"mixed,omitempty"`
	Socks4a     *Socks4a            `json:"socks4a,omitempty"`
	Tproxy      *Tproxy             `json:"tproxy,omitempty"`
	Redir       *Redir              `json:"redir,omitempty"`
	Tun         *Tun                `json:"tun,omitempty"`
	ReverseHttp *ReverseHttp        `json:"reverse_http,omitempty"`
	ReverseTcp  *ReverseTcp         `json:"reverse_tcp,omitempty"`
	None        *Empty              `json:"none,omitempty"`
}

type Transport struct {
	Protocol TransportProtocol `json:"transport"`
}

type TransportProtocolType int32

const (
	TransportProtocolTypeNormal    TransportProtocolType = 0
	TransportProtocolTypeTls       TransportProtocolType = 1
	TransportProtocolTypeMux       TransportProtocolType = 2
	TransportProtocolTypeHttp2     TransportProtocolType = 3
	TransportProtocolTypeWebsocket TransportProtocolType = 4
	TransportProtocolTypeGrpc      TransportProtocolType = 5
	TransportProtocolTypeReality   TransportProtocolType = 6
	TransportProtocolTypeTlsAuto   TransportProtocolType = 7
	TransportProtocolTypeHttpMock  TransportProtocolType = 8
	TransportProtocolTypeAead      TransportProtocolType = 9
	TransportProtocolTypeProxy     TransportProtocolType = 10
)

type TransportProtocol struct {
	Type      TransportProtocolType `json:"type"`
	Normal    *Normal               `json:"normal,omitempty"`
	Tls       *Tls                  `json:"tls,omitempty"`
	Mux       *Mux                  `json:"mux,omitempty"`
	Http2     *Http2                `json:"http2,omitempty"`
	Websocket *Websocket            `json:"websocket,omitempty"`
	Grpc      *Grpc                 `json:"grpc,omitempty"`
	Reality   *Reality              `json:"reality,omitempty"`
	TlsAuto   *TlsAuto              `json:"tls_auto,omitempty"`
	HttpMock  *HttpMock             `json:"http_mock,omitempty"`
	Aead      *Aead                 `json:"aead,omitempty"`
	Proxy     *Proxy                `json:"proxy,omitempty"`
}

type Empty struct{}

type Mux struct{}

type TcpUdpControl int32

const (
	TcpUdpControlAll        TcpUdpControl = 0
	TcpUdpControlDisableTcp TcpUdpControl = 1
	TcpUdpControlDisableUdp TcpUdpControl = 2
)

type Tcpudp struct {
	Host             string        `json:"host"`
	Control          TcpUdpControl `json:"control"`
	UdpHappyEyeballs bool          `json:"udp_happy_eyeballs"`
}

type Quic struct {
	Host string                `json:"host"`
	Tls  *node.TlsServerConfig `json:"tls"`
}

type Http struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Socks5 struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Udp      bool   `json:"udp"`
}

type Socks4a struct {
	Username string `json:"username"`
}

type Mixed struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Redir struct {
	Host string `json:"host"`
}

type Tproxy struct {
	Host         string `json:"host"`
	DnsHijacking bool   `json:"dns_hijacking"`
	ForceFakeip  bool   `json:"force_fakeip"`
}

type TunPlatform struct {
	Darwin *TunPlatformDarwin `json:"darwin"`
}

type TunPlatformDarwin struct {
	NetworkService string `json:"network_service"`
}

type Tun struct {
	Name          string         `json:"name"`
	Mtu           int32          `json:"mtu"`
	ForceFakeip   bool           `json:"force_fakeip"`
	SkipMulticast bool           `json:"skip_multicast"`
	Driver        EndpointDriver `json:"driver"`
	Portal        string         `json:"portal"`
	PortalV6      string         `json:"portal_v6"`
	Route         *Route         `json:"route"`
	PostUp        []string       `json:"post_up"`
	PostDown      []string       `json:"post_down"`
	Platform      *TunPlatform   `json:"platform"`
}

type EndpointDriver int32

const (
	EndpointDriverFdbased      EndpointDriver = 0
	EndpointDriverChannel      EndpointDriver = 1
	EndpointDriverSystemGvisor EndpointDriver = 2
)

type Route struct {
	Routes   []string `json:"routes"`
	Excludes []string `json:"excludes"`
}

type Yuubinsya struct {
	Password    string `json:"password"`
	UdpCoalesce bool   `json:"udp_coalesce"`
}

type Normal struct{}

type Websocket struct{}

type Tls struct {
	Tls *node.TlsServerConfig `json:"tls"`
}

type Grpc struct{}

type Http2 struct{}

type Reality struct {
	ShortId     []string `json:"short_id"`
	ServerName  []string `json:"server_name"`
	Dest        string   `json:"dest"`
	PrivateKey  string   `json:"private_key"`
	PublicKey   string   `json:"public_key"`
	Mldsa65Seed string   `json:"mldsa65_seed"`
	Debug       bool     `json:"debug"`
}

type TlsAuto struct {
	Servernames []string   `json:"servernames"`
	NextProtos  []string   `json:"next_protos"`
	CaCert      []byte     `json:"ca_cert"`
	CaKey       []byte     `json:"ca_key"`
	Ech         *EchConfig `json:"ech"`
}

type EchConfig struct {
	Enable     bool   `json:"enable"`
	Config     []byte `json:"config"`
	PrivateKey []byte `json:"private_key"`
	OuterSNI   string `json:"OuterSNI"`
}

type Sniff struct {
	Enabled bool `json:"enabled"`
}

type ReverseHttp struct {
	Url string          `json:"url"`
	Tls *node.TlsConfig `json:"tls"`
}

type ReverseTcp struct {
	Host string `json:"host"`
}

type HttpMock struct {
	Data []byte `json:"data"`
}

type Aead struct {
	Password     string                `json:"password"`
	CryptoMethod node.AeadCryptoMethod `json:"crypto_method"`
}

type Proxy struct{}
