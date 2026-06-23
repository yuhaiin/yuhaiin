package node

type ProtocolType int32

const (
	ProtocolTypeShadowsocks          ProtocolType = 0
	ProtocolTypeShadowsocksr         ProtocolType = 1
	ProtocolTypeVmess                ProtocolType = 2
	ProtocolTypeWebsocket            ProtocolType = 3
	ProtocolTypeQuic                 ProtocolType = 4
	ProtocolTypeObfsHttp             ProtocolType = 5
	ProtocolTypeTrojan               ProtocolType = 6
	ProtocolTypeSimple               ProtocolType = 7
	ProtocolTypeNone                 ProtocolType = 8
	ProtocolTypeSocks5               ProtocolType = 9
	ProtocolTypeHttp                 ProtocolType = 10
	ProtocolTypeDirect               ProtocolType = 11
	ProtocolTypeReject               ProtocolType = 12
	ProtocolTypeYuubinsya            ProtocolType = 13
	ProtocolTypeGrpc                 ProtocolType = 14
	ProtocolTypeHttp2                ProtocolType = 15
	ProtocolTypeReality              ProtocolType = 16
	ProtocolTypeTls                  ProtocolType = 17
	ProtocolTypeWireguard            ProtocolType = 18
	ProtocolTypeMux                  ProtocolType = 19
	ProtocolTypeDrop                 ProtocolType = 20
	ProtocolTypeVless                ProtocolType = 21
	ProtocolTypeBootstrapDnsWarp     ProtocolType = 22
	ProtocolTypeTailscale            ProtocolType = 23
	ProtocolTypeSet                  ProtocolType = 24
	ProtocolTypeTlsTermination       ProtocolType = 25
	ProtocolTypeHttpTermination      ProtocolType = 26
	ProtocolTypeHttpMock             ProtocolType = 27
	ProtocolTypeAead                 ProtocolType = 28
	ProtocolTypeFixed                ProtocolType = 29
	ProtocolTypeNetworkSplit         ProtocolType = 30
	ProtocolTypeCloudflareWarpMasque ProtocolType = 31
	ProtocolTypeProxy                ProtocolType = 32
	ProtocolTypeFixedv2              ProtocolType = 33
)

type Protocol struct {
	Type                 ProtocolType          `json:"type"`
	Shadowsocks          *Shadowsocks          `json:"shadowsocks,omitempty"`
	Shadowsocksr         *Shadowsocksr         `json:"shadowsocksr,omitempty"`
	Vmess                *Vmess                `json:"vmess,omitempty"`
	Websocket            *Websocket            `json:"websocket,omitempty"`
	Quic                 *Quic                 `json:"quic,omitempty"`
	ObfsHttp             *ObfsHttp             `json:"obfs_http,omitempty"`
	Trojan               *Trojan               `json:"trojan,omitempty"`
	Simple               *Simple               `json:"simple,omitempty"`
	None                 *None                 `json:"none,omitempty"`
	Socks5               *Socks5               `json:"socks5,omitempty"`
	Http                 *Http                 `json:"http,omitempty"`
	Direct               *Direct               `json:"direct,omitempty"`
	Reject               *Reject               `json:"reject,omitempty"`
	Yuubinsya            *Yuubinsya            `json:"yuubinsya,omitempty"`
	Grpc                 *Grpc                 `json:"grpc,omitempty"`
	Http2                *Http2                `json:"http2,omitempty"`
	Reality              *Reality              `json:"reality,omitempty"`
	Tls                  *TlsConfig            `json:"tls,omitempty"`
	Wireguard            *Wireguard            `json:"wireguard,omitempty"`
	Mux                  *Mux                  `json:"mux,omitempty"`
	Drop                 *Drop                 `json:"drop,omitempty"`
	Vless                *Vless                `json:"vless,omitempty"`
	BootstrapDnsWarp     *BootstrapDnsWarp     `json:"bootstrap_dns_warp,omitempty"`
	Tailscale            *Tailscale            `json:"tailscale,omitempty"`
	Set                  *Set                  `json:"set,omitempty"`
	TlsTermination       *TlsTermination       `json:"tls_termination,omitempty"`
	HttpTermination      *HttpTermination      `json:"http_termination,omitempty"`
	HttpMock             *HttpMock             `json:"http_mock,omitempty"`
	Aead                 *Aead                 `json:"aead,omitempty"`
	Fixed                *Fixed                `json:"fixed,omitempty"`
	NetworkSplit         *NetworkSplit         `json:"network_split,omitempty"`
	CloudflareWarpMasque *CloudflareWarpMasque `json:"cloudflare_warp_masque,omitempty"`
	Proxy                *Proxy                `json:"proxy,omitempty"`
	Fixedv2              *Fixedv2              `json:"fixedv2,omitempty"`
}

type Socks5 struct {
	Hostname     string `json:"hostname"`
	User         string `json:"user"`
	Password     string `json:"password"`
	OverridePort uint32 `json:"override_port"`
}

type Http struct {
	User     string `json:"user"`
	Password string `json:"password"`
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
	Obfsparam  string `json:"obfsparam"`
	Protocol   string `json:"protocol"`
	Protoparam string `json:"protoparam"`
}

type Http2 struct {
	Concurrency int32 `json:"concurrency"`
}

type Vmess struct {
	Uuid     string `json:"id"`
	AlterId  string `json:"aid"`
	Security string `json:"security"`
}

type Vless struct {
	Uuid string `json:"uuid"`
}

type Trojan struct {
	Password string `json:"password"`
	Peer     string `json:"peer"`
}

type Yuubinsya struct {
	Password      string `json:"password"`
	UdpOverStream bool   `json:"udp_over_stream"`
	UdpCoalesce   bool   `json:"udp_coalesce"`
}

type Websocket struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type Grpc struct {
	Tls *TlsConfig `json:"tls"`
}

type Quic struct {
	Host string     `json:"host"`
	Tls  *TlsConfig `json:"tls"`
}

type Reality struct {
	ServerName    string `json:"server_name"`
	PublicKey     string `json:"public_key"`
	Mldsa65Verify string `json:"mldsa65_verify"`
	ShortId       string `json:"short_id"`
	Debug         bool   `json:"debug"`
}

type ObfsHttp struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type None struct{}

type Simple struct {
	Host             string `json:"host"`
	Port             int32  `json:"port"`
	AlternateHost    []Host `json:"alternate_host"`
	NetworkInterface string `json:"network_interface"`
}

type Fixed struct {
	Host             string `json:"host"`
	Port             int32  `json:"port"`
	AlternateHost    []Host `json:"alternate_host"`
	NetworkInterface string `json:"network_interface"`
}

type TlsConfig struct {
	Enable             bool     `json:"enable"`
	ServerNames        []string `json:"servernames"`
	CaCert             [][]byte `json:"ca_cert"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	NextProtos         []string `json:"next_protos"`
	EchConfig          []byte   `json:"ech_config"`
}

type Certificate struct {
	Cert         []byte `json:"cert"`
	Key          []byte `json:"key"`
	CertFilePath string `json:"cert_file_path"`
	KeyFilePath  string `json:"key_file_path"`
}

type TlsServerConfig struct {
	Certificates          []Certificate          `json:"certificates"`
	NextProtos            []string               `json:"next_protos"`
	ServerNameCertificate map[string]Certificate `json:"server_name_certificate"`
}

type TlsTermination struct {
	Tls *TlsServerConfig `json:"tls"`
}

type HttpTermination struct {
	Headers map[string]HttpHeaders `json:"headers"`
}

type HttpHeaders struct {
	Headers []HttpHeader `json:"headers"`
}

type HttpHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Direct struct {
	NetworkInterface string `json:"network_interface"`
}

type Reject struct{}

type Drop struct{}

type Host struct {
	Host string `json:"host"`
	Port int32  `json:"port"`
}

type WireguardPeerConfig struct {
	PublicKey    string   `json:"public_key"`
	PreSharedKey string   `json:"pre_shared_key"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    int32    `json:"keep_alive"`
	AllowedIps   []string `json:"allowed_ips"`
}

type Wireguard struct {
	SecretKey string                `json:"secret_key"`
	Endpoint  []string              `json:"endpoint"`
	Peers     []WireguardPeerConfig `json:"peers"`
	Mtu       int32                 `json:"mtu"`
	Reserved  []byte                `json:"reserved"`
}

type Mux struct {
	Concurrency int32 `json:"concurrency"`
}

type BootstrapDnsWarp struct{}

type Tailscale struct {
	AuthKey    string `json:"auth_key"`
	Hostname   string `json:"hostname"`
	ControlUrl string `json:"control_url"`
	Debug      bool   `json:"debug"`
}

type Set struct {
	Nodes    []string     `json:"nodes"`
	Strategy StrategyType `json:"strategy"`
}

type StrategyType int32

const (
	StrategyTypeRandom     StrategyType = 0
	StrategyTypeRoundRobin StrategyType = 1
)

type HttpMock struct {
	Data []byte `json:"data"`
}

type AeadCryptoMethod int32

const (
	AeadCryptoMethodChacha20Poly1305  AeadCryptoMethod = 0
	AeadCryptoMethodXChacha20Poly1305 AeadCryptoMethod = 1
)

type Aead struct {
	Password     string           `json:"password"`
	CryptoMethod AeadCryptoMethod `json:"crypto_method"`
}

type NetworkSplit struct {
	Tcp *Protocol `json:"tcp"`
	Udp *Protocol `json:"udp"`
}

type CloudflareWarpMasque struct {
	PrivateKey        string   `json:"private_key"`
	Endpoint          string   `json:"endpoint"`
	EndpointPublicKey string   `json:"endpoint_public_key"`
	LocalAddresses    []string `json:"local_addresses"`
	Mtu               int32    `json:"mtu"`
}

type Proxy struct{}

type Fixedv2 struct {
	Addresses        []Fixedv2Address `json:"addresses"`
	UdpHappyEyeballs bool             `json:"udp_happy_eyeballs"`
}

type Fixedv2Address struct {
	Host             string `json:"host"`
	NetworkInterface string `json:"network_interface"`
}
