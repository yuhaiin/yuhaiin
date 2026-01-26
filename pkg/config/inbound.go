package config

import "github.com/Asutorufa/yuhaiin/pkg/protocol"

type InboundConfig struct {
	HijackDns       bool                `json:"hijack_dns,omitempty"`
	HijackDnsFakeip bool                `json:"hijack_dns_fakeip,omitempty"`
	Inbounds        map[string]*Inbound `json:"inbounds,omitempty"`
	Sniff           *Sniff              `json:"sniff,omitempty"`
}

type Inbound struct {
	Name      string       `json:"name,omitempty"`
	Enabled   bool         `json:"enabled,omitempty"`
	Empty     *Empty       `json:"empty,omitempty"`
	Tcpudp    *Tcpudp      `json:"tcpudp,omitempty"`
	Quic      *InboundQuic `json:"quic,omitempty"`
	Transport []*Transport `json:"transport,omitempty"`

	Http        *InboundHttp `json:"http,omitempty"`
	Socks5      *InboundSocks5 `json:"socks5,omitempty"`
	Yuubinsya   *InboundYuubinsya `json:"yuubinsya,omitempty"`
	Mix         *Mixed       `json:"mixed,omitempty"`
	Socks4a     *Socks4a     `json:"socks4a,omitempty"`
	Tproxy      *Tproxy      `json:"tproxy,omitempty"`
	Redir       *Redir       `json:"redir,omitempty"`
	Tun         *Tun         `json:"tun,omitempty"`
	ReverseHttp *ReverseHttp `json:"reverse_http,omitempty"`
	ReverseTcp  *ReverseTcp  `json:"reverse_tcp,omitempty"`
	None        *Empty       `json:"none,omitempty"`
}

type Transport struct {
	Normal    *Normal      `json:"normal,omitempty"`
	Tls       *InboundTls  `json:"tls,omitempty"`
	Mux       *Mux         `json:"mux,omitempty"`
	Http2     *Http2       `json:"http2,omitempty"`
	Websocket *Websocket   `json:"websocket,omitempty"`
	Grpc      *Grpc        `json:"grpc,omitempty"`
	Reality   *Reality     `json:"reality,omitempty"`
	TlsAuto   *TlsAuto     `json:"tls_auto,omitempty"`
	HttpMock  *HttpMock    `json:"http_mock,omitempty"`
	Aead      *InboundAead `json:"aead,omitempty"`
	Proxy     *Proxy       `json:"proxy,omitempty"`
}

type Empty struct{}

type Mux struct{}

type TcpUdpControl int32

const (
	TcpUdpControlAll TcpUdpControl = 0
	DisableTcp       TcpUdpControl = 1
	DisableUdp       TcpUdpControl = 2
)

type Tcpudp struct {
	Host             string        `json:"host,omitempty"`
	Control          TcpUdpControl `json:"control,omitempty"`
	UdpHappyEyeballs bool          `json:"udp_happy_eyeballs,omitempty"`
}

type InboundQuic struct {
	Host string                    `json:"host,omitempty"`
	Tls  *protocol.TlsServerConfig `json:"tls,omitempty"`
}

type InboundHttp struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type InboundSocks5 struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Udp      bool   `json:"udp,omitempty"`
}

type Socks4a struct {
	Username string `json:"username,omitempty"`
}

type Mixed struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Redir struct {
	Host string `json:"host,omitempty"`
}

type Tproxy struct {
	Host         string `json:"host,omitempty"`
	DnsHijacking bool   `json:"dns_hijacking,omitempty"`
	ForceFakeip  bool   `json:"force_fakeip,omitempty"`
}

type TunPlatfrom struct {
	Darwin *PlatformDarwin `json:"darwin,omitempty"`
}

type PlatformDarwin struct {
	NetworkService string `json:"network_service,omitempty"`
}

type EndpointDriver int32

const (
	EndpointDriverFdbased      EndpointDriver = 0
	EndpointDriverChannel      EndpointDriver = 1
	EndpointDriverSystemGvisor EndpointDriver = 2
)

type Tun struct {
	Name          string         `json:"name,omitempty"`
	Mtu           int32          `json:"mtu,omitempty"`
	ForceFakeip   bool           `json:"force_fakeip,omitempty"`
	SkipMulticast bool           `json:"skip_multicast,omitempty"`
	Driver        EndpointDriver `json:"driver,omitempty"`
	Portal        string         `json:"portal,omitempty"`
	PortalV6      string         `json:"portal_v6,omitempty"`
	Route         *Route         `json:"route,omitempty"`
	PostUp        []string       `json:"post_up,omitempty"`
	PostDown      []string       `json:"post_down,omitempty"`
	Platform      *TunPlatfrom   `json:"platform,omitempty"`
}

type Route struct {
	Routes   []string `json:"routes,omitempty"`
	Excludes []string `json:"excludes,omitempty"`
}

type InboundYuubinsya struct {
	Password    string `json:"password,omitempty"`
	UdpCoalesce bool   `json:"udp_coalesce,omitempty"`
}

type Normal struct{}

type Websocket struct{}

type InboundTls struct {
	Tls *protocol.TlsServerConfig `json:"tls,omitempty"`
}

type Grpc struct{}

type Http2 struct{}

type Reality struct {
	ShortId     []string `json:"short_id,omitempty"`
	ServerName  []string `json:"server_name,omitempty"`
	Dest        string   `json:"dest,omitempty"`
	PrivateKey  string   `json:"private_key,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	Mldsa65Seed string   `json:"mldsa65_seed,omitempty"`
	Debug       bool     `json:"debug,omitempty"`
}

type TlsAuto struct {
	Servernames []string   `json:"servernames,omitempty"`
	NextProtos  []string   `json:"next_protos,omitempty"`
	CaCert      []byte     `json:"ca_cert,omitempty"`
	CaKey       []byte     `json:"ca_key,omitempty"`
	Ech         *EchConfig `json:"ech,omitempty"`
}

type EchConfig struct {
	Enable     bool   `json:"enable,omitempty"`
	Config     []byte `json:"config,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
	OuterSNI   string `json:"OuterSNI,omitempty"`
}

type Sniff struct {
	Enabled bool `json:"enabled,omitempty"`
}

type ReverseHttp struct {
	Url string              `json:"url,omitempty"`
	Tls *protocol.TlsConfig `json:"tls,omitempty"`
}

type ReverseTcp struct {
	Host string `json:"host,omitempty"`
}

type HttpMock struct {
	Data []byte `json:"data,omitempty"`
}

type InboundAead struct {
	Password     string                    `json:"password,omitempty"`
	CryptoMethod protocol.AeadCryptoMethod `json:"crypto_method,omitempty"`
}

type Proxy struct{}
