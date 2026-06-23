package protocol

type Protocol struct {
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
	Hostname     string `json:"hostname,omitempty"`
	User         string `json:"user,omitempty"`
	Password     string `json:"password,omitempty"`
	OverridePort uint32 `json:"override_port,omitempty"`
}

type Http struct {
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

type Shadowsocks struct {
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}

type Shadowsocksr struct {
	Server     string `json:"server,omitempty"`
	Port       string `json:"port,omitempty"`
	Method     string `json:"method,omitempty"`
	Password   string `json:"password,omitempty"`
	Obfs       string `json:"obfs,omitempty"`
	Obfsparam  string `json:"obfsparam,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Protoparam string `json:"protoparam,omitempty"`
}

type Http2 struct {
	Concurrency int32 `json:"concurrency,omitempty"`
}

type Vmess struct {
	Uuid     string `json:"id,omitempty"`
	AlterId  string `json:"aid,omitempty"`
	Security string `json:"security,omitempty"`
}

type Vless struct {
	Uuid string `json:"uuid,omitempty"`
}

type Trojan struct {
	Password string `json:"password,omitempty"`
	Peer     string `json:"peer,omitempty"`
}

type Yuubinsya struct {
	Password      string `json:"password,omitempty"`
	UdpOverStream bool   `json:"udp_over_stream,omitempty"`
	UdpCoalesce   bool   `json:"udp_coalesce,omitempty"`
}

type Websocket struct {
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
}

type Grpc struct {
	Tls *TlsConfig `json:"tls,omitempty"`
}

type Quic struct {
	Host string     `json:"host,omitempty"`
	Tls  *TlsConfig `json:"tls,omitempty"`
}

type Reality struct {
	ServerName    string `json:"server_name,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	Mldsa65Verify string `json:"mldsa65_verify,omitempty"`
	ShortId       string `json:"short_id,omitempty"`
	Debug         bool   `json:"debug,omitempty"`
}

type ObfsHttp struct {
	Host string `json:"host,omitempty"`
	Port string `json:"port,omitempty"`
}

type None struct{}

// Deprecated: use [Fixed] instead
type Simple struct {
	Host             string  `json:"host,omitempty"`
	Port             int32   `json:"port,omitempty"`
	AlternateHost    []*Host `json:"alternate_host,omitempty"`
	NetworkInterface string  `json:"network_interface,omitempty"`
}

type Fixed struct {
	Host             string  `json:"host,omitempty"`
	Port             int32   `json:"port,omitempty"`
	AlternateHost    []*Host `json:"alternate_host,omitempty"`
	NetworkInterface string  `json:"network_interface,omitempty"`
}

type TlsConfig struct {
	Enable             bool     `json:"enable,omitempty"`
	ServerNames        []string `json:"servernames,omitempty"`
	CaCert             [][]byte `json:"ca_cert,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty"`
	NextProtos         []string `json:"next_protos,omitempty"`
	EchConfig          []byte   `json:"ech_config,omitempty"`
}

type Certificate struct {
	Cert         []byte `json:"cert,omitempty"`
	Key          []byte `json:"key,omitempty"`
	CertFilePath string `json:"cert_file_path,omitempty"`
	KeyFilePath  string `json:"key_file_path,omitempty"`
}

type TlsServerConfig struct {
	Certificates          []*Certificate          `json:"certificates,omitempty"`
	NextProtos            []string                `json:"next_protos,omitempty"`
	ServerNameCertificate map[string]*Certificate `json:"server_name_certificate,omitempty"`
}

type TlsTermination struct {
	Tls *TlsServerConfig `json:"tls,omitempty"`
}

type HttpTermination struct {
	Headers map[string]*HttpHeaders `json:"headers,omitempty"`
}

type HttpHeaders struct {
	Headers []*HttpHeader `json:"headers,omitempty"`
}

type HttpHeader struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type Direct struct {
	NetworkInterface string `json:"network_interface,omitempty"`
}

type Reject struct{}

type Drop struct{}

type Host struct {
	Host string `json:"host,omitempty"`
	Port int32  `json:"port,omitempty"`
}

type WireguardPeerConfig struct {
	PublicKey    string   `json:"public_key,omitempty"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	KeepAlive    int32    `json:"keep_alive,omitempty"`
	AllowedIps   []string `json:"allowed_ips,omitempty"`
}

type Wireguard struct {
	SecretKey string                 `json:"secret_key,omitempty"`
	Endpoint  []string               `json:"endpoint,omitempty"`
	Peers     []*WireguardPeerConfig `json:"peers,omitempty"`
	Mtu       int32                  `json:"mtu,omitempty"`
	Reserved  []byte                 `json:"reserved,omitempty"`
}

type Mux struct {
	Concurrency int32 `json:"concurrency,omitempty"`
}

type BootstrapDnsWarp struct{}

type Tailscale struct {
	AuthKey    string `json:"auth_key,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	ControlUrl string `json:"control_url,omitempty"`
	Debug      bool   `json:"debug,omitempty"`
}

type StrategyType int32

const (
	StrategyRandom     StrategyType = 0
	StrategyRoundRobin StrategyType = 1
)

type Set struct {
	Nodes    []string     `json:"nodes,omitempty"`
	Strategy StrategyType `json:"strategy,omitempty"`
}

type HttpMock struct {
	Data []byte `json:"data,omitempty"`
}

type AeadCryptoMethod int32

const (
	AeadChacha20Poly1305  AeadCryptoMethod = 0
	AeadXChacha20Poly1305 AeadCryptoMethod = 1
)

type Aead struct {
	Password     string           `json:"password,omitempty"`
	CryptoMethod AeadCryptoMethod `json:"crypto_method,omitempty"`
}

type NetworkSplit struct {
	Tcp *Protocol `json:"tcp,omitempty"`
	Udp *Protocol `json:"udp,omitempty"`
}

type CloudflareWarpMasque struct {
	PrivateKey        string   `json:"private_key,omitempty"`
	Endpoint          string   `json:"endpoint,omitempty"`
	EndpointPublicKey string   `json:"endpoint_public_key,omitempty"`
	LocalAddresses    []string `json:"local_addresses,omitempty"`
	Mtu               int32    `json:"mtu,omitempty"`
}

type Proxy struct{}

type Fixedv2 struct {
	Addresses        []*Fixedv2Address `json:"addresses,omitempty"`
	UdpHappyEyeballs bool              `json:"udp_happy_eyeballs,omitempty"`
}

type Fixedv2Address struct {
	Host             string `json:"host,omitempty"`
	NetworkInterface string `json:"network_interface,omitempty"`
}
