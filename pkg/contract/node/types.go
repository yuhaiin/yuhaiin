package node

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
)

type IPVersion string

const (
	IPVersionAuto IPVersion = "auto"
	IPVersionIPv4 IPVersion = "ipv4"
	IPVersionIPv6 IPVersion = "ipv6"
)

type Node struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Group     string         `json:"group"`
	Origin    string         `json:"origin"`
	Enabled   bool           `json:"enabled"`
	IPVersion IPVersion      `json:"ip_version,omitempty"`
	Chain     []Protocol     `json:"chain" privilege:"secrets:bound"`
	Latency   *LatencyConfig `json:"latency,omitzero"`
}

// LatencyConfig overrides the global HTTP latency target for one node.
type LatencyConfig struct {
	URL                string `json:"url,omitempty" secret:"url"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitzero"`
}

type Selection struct {
	TCP *Node `json:"tcp,omitzero"`
	UDP *Node `json:"udp,omitzero"`
}

type SelectionRequest struct {
	TCPID string `json:"tcpId"`
	UDPID string `json:"udpId"`
}

type ImportRequest struct {
	Text  string `json:"text"`
	Group string `json:"group"`
}

type ImportIssue struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type ImportPreview struct {
	Items  []Node        `json:"items"`
	Errors []ImportIssue `json:"errors"`
}

// Selector is an independently named choice of node shared by routing rules.
// Its chosen node may itself use a Set protocol chain.
type Selector struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	NodeID   string          `json:"nodeId"`
	Revision uint64          `json:"revision"`
	Policy   *SelectorPolicy `json:"policy,omitzero"`
}

type SelectorList struct {
	Items []Selector `json:"items"`
}

type LatencyRequest struct {
	Type         string `json:"type"`
	URL          string `json:"url" secret:"url"`
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
	CredentialRef string `json:"credentialRef,omitempty"`
	Type          string `json:"type"`

	Shadowsocks  *Shadowsocks  `json:"shadowsocks,omitzero"`
	Shadowsocksr *Shadowsocksr `json:"shadowsocksr,omitzero"`
	Vmess        *Vmess        `json:"vmess,omitzero"`
	Websocket    *Websocket    `json:"websocket,omitzero"`
	Hysteria2    *Hysteria2    `json:"hysteria2,omitzero"`
	Quic         *Quic         `json:"quic,omitzero"`
	ObfsHTTP     *ObfsHTTP     `json:"obfs_http,omitzero"`
	Trojan       *Trojan       `json:"trojan,omitzero"`
	Simple       *Fixed        `json:"simple,omitzero"`
	None         *None         `json:"none,omitzero"`
	Socks5       *Socks5       `json:"socks5,omitzero"`
	SSH          *SSH          `json:"ssh,omitzero"`
	HTTP         *HTTP         `json:"http,omitzero"`
	Direct       *Direct       `json:"direct,omitzero"`
	Reject       *Reject       `json:"reject,omitzero"`
	Yuubinsya    *Yuubinsya    `json:"yuubinsya,omitzero"`
	HTTP2        *Concurrency  `json:"http2,omitzero"`
	Reality      *Reality      `json:"reality,omitzero"`
	TLS          *TLS          `json:"tls,omitzero"`
	AmneziaWG    *AmneziaWG    `json:"amneziawg,omitzero"`
	Nebula       *Nebula       `json:"nebula,omitzero"`
	ZeroTier     *ZeroTier     `json:"zerotier,omitzero"`
	// Additional client-only enterprise VPN protocols.
	IKEv2                *IKEv2                `json:"ikev2,omitzero"`
	AnyConnect           *AnyConnect           `json:"anyconnect,omitzero"`
	SSTP                 *SSTP                 `json:"sstp,omitzero"`
	Fortinet             *Fortinet             `json:"fortinet,omitzero"`
	Wireguard            *Wireguard            `json:"wireguard,omitzero"`
	OpenVPN              *OpenVPN              `json:"openvpn,omitzero"`
	L2TP                 *L2TP                 `json:"l2tp,omitzero"`
	L2TPv3               *L2TPv3               `json:"l2tpv3,omitzero"`
	GlobalProtect        *GlobalProtect        `json:"globalprotect,omitzero"`
	SoftEther            *SoftEther            `json:"softether,omitzero"`
	Mux                  *Concurrency          `json:"mux,omitzero"`
	Drop                 *Drop                 `json:"drop,omitzero"`
	Vless                *Vless                `json:"vless,omitzero"`
	BootstrapDNSWarp     *BootstrapDNSWarp     `json:"bootstrap_dns_warp,omitzero"`
	Tailscale            *Tailscale            `json:"tailscale,omitzero"`
	Set                  *Set                  `json:"set,omitzero"`
	TLSTermination       *TLSTermination       `json:"tls_termination,omitzero"`
	HTTPMock             *HTTPMock             `json:"http_mock,omitzero"`
	AEAD                 *AEAD                 `json:"aead,omitzero"`
	Fixed                *Fixed                `json:"fixed,omitzero"`
	NetworkSplit         *NetworkSplit         `json:"network_split,omitzero"`
	CloudflareWarpMasque *CloudflareWarpMasque `json:"cloudflare_warp_masque,omitzero"`
	Masque               *Masque               `json:"masque,omitzero"`
	Proxy                *Proxy                `json:"proxy,omitzero"`
	FixedV2              *FixedV2              `json:"fixedv2,omitzero"`
	PointAsEndpoint      *PointAsEndpoint      `json:"point_as_endpoint,omitzero"`
}

// L2TP is a UDP client LAC with userspace PPP. It does not enable IPsec.
type L2TP struct {
	AuthType      string `json:"auth_type,omitzero"`
	Gateway       string `json:"gateway"`
	Username      string `json:"username,omitzero"`
	Password      string `json:"password,omitzero" secret:"true"`
	SharedSecret  string `json:"shared_secret,omitzero" secret:"true"`
	Hostname      string `json:"hostname,omitzero"`
	IPv6          bool   `json:"ipv6,omitzero"`
	IPv6Address   string `json:"ipv6_address,omitzero"`
	MTU           int32  `json:"mtu,omitzero"`
	AutoReconnect bool   `json:"auto_reconnect,omitzero"`
}

// L2TPv3 carries an Ethernet pseudowire over UDP. IP addresses and routers
// belong to the userspace stack. Static sessions require prearranged peer IDs.
type L2TPv3 struct {
	LocalAddress   string `json:"local_address,omitzero"`
	Gateway        string `json:"gateway"`
	Hostname       string `json:"hostname,omitzero"`
	SharedSecret   string `json:"shared_secret,omitzero" secret:"true"`
	Static         bool   `json:"static,omitzero"`
	LocalSessionID uint32 `json:"local_session_id,omitzero"`
	PeerSessionID  uint32 `json:"peer_session_id,omitzero"`
	LocalCookie    string `json:"local_cookie,omitzero" secret:"true"`
	PeerCookie     string `json:"peer_cookie,omitzero" secret:"true"`
	Sublayer       bool   `json:"sublayer,omitzero"`
	RemoteEndID    string `json:"remote_end_id,omitzero"`
	Address        string `json:"address,omitzero"`
	Router         string `json:"router,omitzero"`
	IPv6Address    string `json:"ipv6_address,omitzero"`
	IPv6Router     string `json:"ipv6_router,omitzero"`
	MTU            int32  `json:"mtu,omitzero"`
	AutoReconnect  bool   `json:"auto_reconnect,omitzero"`
}

type L2TPInfo struct {
	TunnelPrefixes []string `json:"tunnel_prefixes,omitempty"`
	DNS            []string `json:"dns,omitempty"`
	Auth           string   `json:"auth,omitempty"`
	PeerAddress    string   `json:"peer_address,omitempty"`
	MTU            int32    `json:"mtu,omitzero"`
	LocalTunnelID  uint32   `json:"local_tunnel_id,omitzero"`
	PeerTunnelID   uint32   `json:"peer_tunnel_id,omitzero"`
	LocalSessionID uint32   `json:"local_session_id,omitzero"`
	PeerSessionID  uint32   `json:"peer_session_id,omitzero"`
}

// OpenVPN is a native TLS client with an in-memory credential configuration.
type OpenVPN struct {
	Gateway            string   `json:"gateway"`
	Network            string   `json:"network,omitzero"`
	CACertPEM          string   `json:"ca_cert_pem,omitzero"`
	ClientCertPEM      string   `json:"client_cert_pem,omitzero"`
	ClientKeyPEM       string   `json:"client_key_pem,omitzero" secret:"true"`
	ServerName         string   `json:"server_name,omitzero"`
	Username           string   `json:"username,omitzero"`
	Password           string   `json:"password,omitzero" secret:"true"`
	TLSAuthKey         string   `json:"tls_auth_key,omitzero" secret:"true"`
	TLSCryptKey        string   `json:"tls_crypt_key,omitzero" secret:"true"`
	KeyDirection       *int32   `json:"key_direction,omitzero"`
	Auth               string   `json:"auth,omitzero"`
	DataCiphers        []string `json:"data_ciphers,omitzero"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitzero"`
	AutoReconnect      bool     `json:"auto_reconnect,omitzero"`
	MTU                int32    `json:"mtu,omitzero"`
	RenegotiateSeconds int32    `json:"renegotiate_seconds,omitzero"`
}

type OpenVPNInfo struct {
	TunnelPrefixes []string `json:"tunnel_prefixes,omitempty"`
	DNS            []string `json:"dns,omitempty"`
	Routes         []string `json:"routes,omitempty"`
	Gateway        string   `json:"gateway,omitempty"`
	Cipher         string   `json:"cipher,omitempty"`
	MTU            int32    `json:"mtu,omitzero"`
}

// GlobalProtect is a directly addressed gateway with password authentication.
// Portal discovery, SAML/SSO and HIP are not supported by this node.
type GlobalProtect struct {
	Gateway            string `json:"gateway"`
	Username           string `json:"username"`
	Password           string `json:"password" secret:"true"`
	Computer           string `json:"computer,omitzero"`
	CACertPEM          string `json:"ca_cert_pem,omitzero"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitzero"`
	MTU                int32  `json:"mtu,omitzero"`
	UseESP             bool   `json:"use_esp,omitzero"`
}

// SoftEther configures the native SSL-VPN protocol (not SSTP).
// The virtual hub must provide DHCP unless Address and Router are set.
type SoftEther struct {
	Gateway            string `json:"gateway"`
	Username           string `json:"username"`
	Password           string `json:"password" secret:"true"`
	Hub                string `json:"hub,omitzero"`
	AuthType           string `json:"auth_type,omitzero"`
	ClientCertPEM      string `json:"client_cert_pem,omitzero"`
	ClientKeyPEM       string `json:"client_key_pem,omitzero" secret:"true"`
	CACertPEM          string `json:"ca_cert_pem,omitzero"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitzero"`
	Address            string `json:"address,omitzero"`
	Router             string `json:"router,omitzero"`
	IPv6Address        string `json:"ipv6_address,omitzero"`
	IPv6Router         string `json:"ipv6_router,omitzero"`
	UDPAcceleration    bool   `json:"udp_acceleration,omitzero"`
	AutoReconnect      bool   `json:"auto_reconnect,omitzero"`
	MTU                int32  `json:"mtu,omitzero"`
}

// NodeExtraInfo contains runtime details returned by an outbound after it has
// connected. It is read from the existing runtime instance and does not start
// a new connection.
type NodeExtraInfo struct {
	L2TP          *L2TPInfo          `json:"l2tp,omitzero"`
	L2TPv3        *L2TPInfo          `json:"l2tpv3,omitzero"`
	OpenVPN       *OpenVPNInfo       `json:"openvpn,omitzero"`
	GlobalProtect *GlobalProtectInfo `json:"globalprotect,omitzero"`
}

// GlobalProtectInfo is the tunnel and network configuration returned by
// GlobalProtect getconfig. Routes are informational and are not applied by
// the GlobalProtect outbound.
type GlobalProtectInfo struct {
	TunnelPrefix                 string   `json:"tunnel_prefix,omitempty"`
	AccessRoutesIPv4             []string `json:"access_routes_ipv4,omitempty"`
	ExcludeRoutesIPv4            []string `json:"exclude_routes_ipv4,omitempty"`
	AccessRoutesIPv6             []string `json:"access_routes_ipv6,omitempty"`
	ExcludeRoutesIPv6            []string `json:"exclude_routes_ipv6,omitempty"`
	DNS                          []string `json:"dns,omitempty"`
	DNSv6                        []string `json:"dns_v6,omitempty"`
	DNSSuffix                    []string `json:"dns_suffix,omitempty"`
	NoDirectAccessToLocalNetwork string   `json:"no_direct_access_to_local_network,omitempty"`
	DataTransport                string   `json:"data_transport,omitempty"`
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
	Password string `json:"password" secret:"true"`
}

type Shadowsocksr struct {
	Server     string `json:"server"`
	Port       string `json:"port"`
	Method     string `json:"method"`
	Password   string `json:"password" secret:"true"`
	Obfs       string `json:"obfs"`
	ObfsParam  string `json:"obfsparam"`
	Protocol   string `json:"protocol"`
	ProtoParam string `json:"protoparam" secret:"true"`
}

type Vmess struct {
	UUID     string `json:"id" secret:"true"`
	AlterID  string `json:"aid"`
	Security string `json:"security"`
}

type Vless struct {
	UUID string `json:"uuid" secret:"true"`
}

type Websocket struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type Quic struct {
	Host string `json:"host"`
	TLS  TLS    `json:"tls,omitzero"`
}

// Hysteria2 bandwidth values are bytes per second; zero selects automatic congestion control.
type Hysteria2 struct {
	Host               string `json:"host"`
	Auth               string `json:"auth" secret:"true"`
	TLS                TLS    `json:"tls,omitzero"`
	UploadBPS          uint64 `json:"upload_bps,omitzero"`
	DownloadBPS        uint64 `json:"download_bps,omitzero"`
	SalamanderPassword string `json:"salamander_password,omitzero" secret:"true"`
	// Additional UDP relays to the same Hysteria server. Host is also included;
	// with this list set, all DNS answers for each hostname enter the hop pool.
	HopAddresses []string `json:"hop_addresses,omitzero"`
	// Port and address hopping share these intervals in seconds;
	// zero selects the upstream default of 30 seconds. Fixed and random
	// intervals are mutually exclusive, and the minimum is five seconds.
	HopIntervalSeconds    uint32 `json:"hop_interval_seconds,omitzero"`
	MinHopIntervalSeconds uint32 `json:"min_hop_interval_seconds,omitzero"`
	MaxHopIntervalSeconds uint32 `json:"max_hop_interval_seconds,omitzero"`
}

func (Hysteria2) ProtocolType() string { return "hysteria2" }

type ObfsHTTP struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type Trojan struct {
	Password string `json:"password" secret:"true"`
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
	Password     string `json:"password" secret:"true"`
	Hostname     string `json:"hostname"`
	OverridePort int32  `json:"override_port,omitzero"`
}

// SSH is an SSH direct-tcpip outbound. The preceding simple/fixed protocol
// specifies the SSH server; host_key pins its public key or SHA256 fingerprint.
type SSH struct {
	User                 string `json:"user"`
	Password             string `json:"password,omitzero" secret:"true"`
	PrivateKey           string `json:"private_key,omitzero" secret:"true"`
	PrivateKeyPassphrase string `json:"private_key_passphrase,omitzero" secret:"true"`
	HostKey              string `json:"host_key"`
	KeepAliveSeconds     int32  `json:"keep_alive_seconds,omitzero"`
}

type HTTP struct {
	User     string `json:"user"`
	Password string `json:"password" secret:"true"`
}

type Yuubinsya struct {
	Password      string `json:"password" secret:"true"`
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
	ShortID       string `json:"short_id,omitzero" secret:"true"`
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
	Key          []byte `json:"key,omitzero" secret:"true"`
	CertFilePath string `json:"cert_file_path,omitzero" privilege:"secrets:manage"`
	KeyFilePath  string `json:"key_file_path,omitzero" privilege:"secrets:manage"`
}

type TLSTermination struct {
	TLS ServerTLS `json:"tls"`
}

// IKEv2 uses ESP over UDP/NAT-T or RFC 8229 TCP encapsulation.
// EAP credentials supplement, rather than replace, authentication of the peer.
type IKEv2 struct {
	Gateway  string `json:"gateway"`
	PSK      string `json:"psk,omitzero" secret:"true"`
	LocalID  string `json:"local_id"`
	ServerID string `json:"server_id,omitzero"`
	Username string `json:"username,omitzero"`
	Password string `json:"password,omitzero" secret:"true"`
	TCP      bool   `json:"tcp,omitzero"`
	MTU      int32  `json:"mtu,omitzero"`
}

type AnyConnect struct {
	Gateway            string `json:"gateway"`
	Username           string `json:"username"`
	Password           string `json:"password" secret:"true"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitzero"`
	DisableDTLS        bool   `json:"disable_dtls,omitzero"`
	MTU                int32  `json:"mtu,omitzero"`
}

type SSTP struct {
	Gateway            string `json:"gateway"`
	Username           string `json:"username"`
	Password           string `json:"password" secret:"true"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitzero"`
	MTU                int32  `json:"mtu,omitzero"`
}

type Fortinet struct {
	Gateway            string `json:"gateway"`
	Username           string `json:"username"`
	Password           string `json:"password" secret:"true"`
	Realm              string `json:"realm,omitzero"`
	Token              string `json:"token,omitzero" secret:"true"`
	TOTPSecret         string `json:"totp_secret,omitzero" secret:"true"`
	CACertPEM          string `json:"ca_cert_pem,omitzero"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitzero"`
	DisableDTLS        bool   `json:"disable_dtls,omitzero"`
	MTU                int32  `json:"mtu,omitzero"`
}

// Nebula embeds a standard client configuration as YAML.
// Certificates and private keys should be supplied inline, not as host file paths.
type Nebula struct {
	ConfigYAML string `json:"config_yaml" secret:"true"`
}

// ZeroTier joins a controller-managed L2 network using an embedded native core.
// Identity is stored under the application data directory and survives restarts.
type ZeroTier struct {
	NetworkID    string         `json:"network_id"`
	Identity     string         `json:"identity,omitzero" secret:"true"`
	Listen       string         `json:"listen,omitzero"`
	LibraryPath  string         `json:"library_path,omitzero" privilege:"system:execute"`
	LowBandwidth bool           `json:"low_bandwidth,omitzero"`
	Moons        []ZeroTierMoon `json:"moons,omitzero"`
}

type ZeroTierMoon struct {
	ID   string `json:"id"`
	Seed string `json:"seed"`
}

type Wireguard struct {
	SecretKey string          `json:"secretKey" secret:"true"`
	Endpoint  []string        `json:"endpoint,omitzero"`
	Peers     []WireguardPeer `json:"peers,omitzero"`
	MTU       int32           `json:"mtu,omitzero"`
	Reserved  []byte          `json:"reserved,omitzero"`
}

// AmneziaWG uses the official amneziawg-go/v3 userspace protocol engine.
// The fields mirror its UAPI; strings retain its uint32 range notation.
type AmneziaWG struct {
	SecretKey              string          `json:"secretKey" secret:"true"`
	Endpoint               []string        `json:"endpoint,omitzero"`
	Peers                  []WireguardPeer `json:"peers,omitzero"`
	MTU                    int32           `json:"mtu,omitzero"`
	JC                     uint32          `json:"jc,omitzero"`
	JMin                   uint32          `json:"jmin,omitzero"`
	JMax                   uint32          `json:"jmax,omitzero"`
	S1                     uint32          `json:"s1,omitzero"`
	S2                     uint32          `json:"s2,omitzero"`
	S3                     uint32          `json:"s3,omitzero"`
	S4                     uint32          `json:"s4,omitzero"`
	H1                     string          `json:"h1,omitzero"`
	H2                     string          `json:"h2,omitzero"`
	H3                     string          `json:"h3,omitzero"`
	H4                     string          `json:"h4,omitzero"`
	I1                     string          `json:"i1,omitzero"`
	I2                     string          `json:"i2,omitzero"`
	I3                     string          `json:"i3,omitzero"`
	I4                     string          `json:"i4,omitzero"`
	I5                     string          `json:"i5,omitzero"`
	HeaderProtectionKey    string          `json:"header_protection_key,omitzero" secret:"true"`
	ContentPaddingAddition string          `json:"content_padding_addition,omitzero"`
	RandomTrailers         bool            `json:"random_trailers,omitzero"`
	DisableCookies         bool            `json:"disable_cookies,omitzero"`
}

type WireguardPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitzero" secret:"true"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    int32    `json:"keepAlive,omitzero"`
	AllowedIPs   []string `json:"allowedIps,omitzero"`
}

type Tailscale struct {
	AuthKey    string `json:"auth_key" secret:"true"`
	Hostname   string `json:"hostname"`
	ControlURL string `json:"control_url" secret:"url"`
	Debug      bool   `json:"debug,omitzero"`
}

type Set struct {
	Nodes    []string `json:"nodes,omitzero"`
	Strategy string   `json:"strategy,omitzero"`
}

type HTTPMock struct {
	Data []byte `json:"data,omitzero" secret:"true"`
}

type AEAD struct {
	Password     string `json:"password" secret:"true"`
	CryptoMethod string `json:"crypto_method"`
}

type NetworkSplit struct {
	TCP *Protocol `json:"tcp,omitzero"`
	UDP *Protocol `json:"udp,omitzero"`
}

type CloudflareWarpMasque struct {
	PrivateKey        string   `json:"private_key" secret:"true"`
	Endpoint          string   `json:"endpoint"`
	EndpointPublicKey string   `json:"endpoint_public_key"`
	LocalAddresses    []string `json:"local_addresses,omitzero"`
	MTU               int32    `json:"mtu,omitzero"`
	Transport         string   `json:"transport,omitzero"`
}

// Masque configures a standards-based RFC 9484 CONNECT-IP client.
type Masque struct {
	Endpoint           string   `json:"endpoint"`
	URL                string   `json:"url" secret:"url"`
	ServerName         string   `json:"server_name,omitzero"`
	CACertPEM          string   `json:"ca_cert_pem,omitzero"`
	ClientCertPEM      string   `json:"client_cert_pem,omitzero"`
	ClientKeyPEM       string   `json:"client_key_pem,omitzero" secret:"true"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitzero"`
	BearerToken        string   `json:"bearer_token,omitzero" secret:"true"`
	LocalAddresses     []string `json:"local_addresses"`
	MTU                int32    `json:"mtu,omitzero"`
	Transport          string   `json:"transport,omitzero"`
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
func (SSH) ProtocolType() string                  { return "ssh" }
func (HTTP) ProtocolType() string                 { return "http" }
func (Direct) ProtocolType() string               { return "direct" }
func (Reject) ProtocolType() string               { return "reject" }
func (Yuubinsya) ProtocolType() string            { return "yuubinsya" }
func (HTTP2) ProtocolType() string                { return "http2" }
func (Reality) ProtocolType() string              { return "reality" }
func (TLS) ProtocolType() string                  { return "tls" }
func (AmneziaWG) ProtocolType() string            { return "amneziawg" }
func (Nebula) ProtocolType() string               { return "nebula" }
func (ZeroTier) ProtocolType() string             { return "zerotier" }
func (IKEv2) ProtocolType() string                { return "ikev2" }
func (AnyConnect) ProtocolType() string           { return "anyconnect" }
func (SSTP) ProtocolType() string                 { return "sstp" }
func (Fortinet) ProtocolType() string             { return "fortinet" }
func (Wireguard) ProtocolType() string            { return "wireguard" }
func (OpenVPN) ProtocolType() string              { return "openvpn" }
func (L2TP) ProtocolType() string                 { return "l2tp" }
func (L2TPv3) ProtocolType() string               { return "l2tpv3" }
func (GlobalProtect) ProtocolType() string        { return "globalprotect" }
func (SoftEther) ProtocolType() string            { return "softether" }
func (Mux) ProtocolType() string                  { return "mux" }
func (Drop) ProtocolType() string                 { return "drop" }
func (Vless) ProtocolType() string                { return "vless" }
func (BootstrapDNSWarp) ProtocolType() string     { return "bootstrap_dns_warp" }
func (Tailscale) ProtocolType() string            { return "tailscale" }
func (Set) ProtocolType() string                  { return "set" }
func (TLSTermination) ProtocolType() string       { return "tls_termination" }
func (HTTPMock) ProtocolType() string             { return "http_mock" }
func (AEAD) ProtocolType() string                 { return "aead" }
func (Fixed) ProtocolType() string                { return "fixed" }
func (NetworkSplit) ProtocolType() string         { return "network_split" }
func (CloudflareWarpMasque) ProtocolType() string { return "cloudflare_warp_masque" }
func (Masque) ProtocolType() string               { return "masque" }
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
	switch x.IPVersion {
	case "", IPVersionAuto, IPVersionIPv4, IPVersionIPv6:
	default:
		return fmt.Errorf("unsupported node IP version %q", x.IPVersion)
	}
	if len(x.Chain) == 0 {
		return errors.New("node chain is empty")
	}
	if x.Latency != nil && strings.TrimSpace(x.Latency.URL) != "" {
		latencyURL, err := url.Parse(strings.TrimSpace(x.Latency.URL))
		if err != nil || latencyURL.Host == "" || (!strings.EqualFold(latencyURL.Scheme, "http") && !strings.EqualFold(latencyURL.Scheme, "https")) {
			return errors.New("node latency URL must be an absolute HTTP or HTTPS URL")
		}
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
	return x.validateCredentialRef()
}

func (x Protocol) presentVariants() map[string]bool {
	return map[string]bool{
		"shadowsocks":            x.Shadowsocks != nil,
		"shadowsocksr":           x.Shadowsocksr != nil,
		"vmess":                  x.Vmess != nil,
		"websocket":              x.Websocket != nil,
		"quic":                   x.Quic != nil,
		"hysteria2":              x.Hysteria2 != nil,
		"obfs_http":              x.ObfsHTTP != nil,
		"trojan":                 x.Trojan != nil,
		"simple":                 x.Simple != nil,
		"none":                   x.None != nil,
		"socks5":                 x.Socks5 != nil,
		"ssh":                    x.SSH != nil,
		"http":                   x.HTTP != nil,
		"direct":                 x.Direct != nil,
		"reject":                 x.Reject != nil,
		"yuubinsya":              x.Yuubinsya != nil,
		"http2":                  x.HTTP2 != nil,
		"reality":                x.Reality != nil,
		"tls":                    x.TLS != nil,
		"amneziawg":              x.AmneziaWG != nil,
		"nebula":                 x.Nebula != nil,
		"zerotier":               x.ZeroTier != nil,
		"ikev2":                  x.IKEv2 != nil,
		"anyconnect":             x.AnyConnect != nil,
		"sstp":                   x.SSTP != nil,
		"fortinet":               x.Fortinet != nil,
		"wireguard":              x.Wireguard != nil,
		"globalprotect":          x.GlobalProtect != nil,
		"openvpn":                x.OpenVPN != nil,
		"l2tp":                   x.L2TP != nil,
		"l2tpv3":                 x.L2TPv3 != nil,
		"softether":              x.SoftEther != nil,
		"mux":                    x.Mux != nil,
		"drop":                   x.Drop != nil,
		"vless":                  x.Vless != nil,
		"bootstrap_dns_warp":     x.BootstrapDNSWarp != nil,
		"tailscale":              x.Tailscale != nil,
		"set":                    x.Set != nil,
		"tls_termination":        x.TLSTermination != nil,
		"http_mock":              x.HTTPMock != nil,
		"aead":                   x.AEAD != nil,
		"fixed":                  x.Fixed != nil,
		"network_split":          x.NetworkSplit != nil,
		"cloudflare_warp_masque": x.CloudflareWarpMasque != nil,
		"masque":                 x.Masque != nil,
		"proxy":                  x.Proxy != nil,
		"fixedv2":                x.FixedV2 != nil,
		"point_as_endpoint":      x.PointAsEndpoint != nil,
	}
}
