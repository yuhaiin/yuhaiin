package protocol

type Origin int32

const (
	OriginReserve Origin = 0
	OriginRemote  Origin = 101
	OriginManual  Origin = 102
)

type Point struct {
	Hash      string      `json:"hash,omitempty"`
	Name      string      `json:"name,omitempty"`
	Group     string      `json:"group,omitempty"`
	Origin    Origin      `json:"origin,omitempty"`
	Protocols []*Protocol `json:"protocols,omitempty"`
}

type NodeConfig struct {
	Tcp     *Point             `json:"tcp,omitempty"`
	Udp     *Point             `json:"udp,omitempty"`
	Links   map[string]*Link   `json:"links,omitempty"`
	Manager *NodeManagerConfig `json:"manager,omitempty"`
}

type NodeManagerConfig struct {
	Nodes     map[string]*Point   `json:"nodes,omitempty"`
	Tags      map[string]*Tags    `json:"tags,omitempty"`
	Publishes map[string]*Publish `json:"publishes,omitempty"`
}

type LinkType int32

const (
	LinkTypeReserve      LinkType = 0
	LinkTypeTrojan       LinkType = 1
	LinkTypeVmess        LinkType = 2
	LinkTypeShadowsocks  LinkType = 3
	LinkTypeShadowsocksr LinkType = 4
)

type Link struct {
	Name string   `json:"name,omitempty"`
	Type LinkType `json:"type,omitempty"`
	Url  string   `json:"url,omitempty"`
}

type Publish struct {
	Points   []string `json:"points,omitempty"`
	Path     string   `json:"path,omitempty"`
	Name     string   `json:"name,omitempty"`
	Password string   `json:"password,omitempty"`
	Address  string   `json:"address,omitempty"`
	Insecure bool     `json:"insecure,omitempty"`
}

type YuhaiinUrl struct {
	Remote *YuhaiinUrlRemote `json:"remote,omitempty"`
	Points *YuhaiinUrlPoints `json:"points,omitempty"`
	Name   string            `json:"name,omitempty"`
}

type YuhaiinUrlRemote struct {
	Publish *Publish `json:"publish,omitempty"`
}

type YuhaiinUrlPoints struct {
	Points []*Point `json:"points,omitempty"`
}

type TagType int32

const (
	TagTypeNode   TagType = 0
	TagTypeMirror TagType = 1
)

type Tags struct {
	Tag  string   `json:"tag,omitempty"`
	Type TagType  `json:"type,omitempty"`
	Hash []string `json:"hash,omitempty"`
}

// Latency Structs

type HttpTest struct {
	Url string `json:"url,omitempty"`
}

type DnsTest struct {
	Host         string `json:"host,omitempty"`
	TargetDomain string `json:"target_name,omitempty"`
}

type DnsOverQuic struct {
	Host         string `json:"host,omitempty"`
	TargetDomain string `json:"target_name,omitempty"`
}

type Ip struct {
	Url       string `json:"url,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type IpResponse struct {
	Ipv4 string `json:"ipv4,omitempty"`
	Ipv6 string `json:"ipv6,omitempty"`
}

type Error struct {
	Msg string `json:"msg,omitempty"`
}

type Stun struct {
	Host string `json:"host,omitempty"`
	Tcp  bool   `json:"tcp,omitempty"`
}

type NatType int32

const (
	NatUnknown                    NatType = 0
	NatNoResult                   NatType = 1
	NatEndpointIndependentNoNAT   NatType = 2
	NatEndpointIndependent        NatType = 3
	NatAddressDependent           NatType = 4
	NatAddressAndPortDependent    NatType = 5
	NatServerNotSupportChangePort NatType = 6
)

type StunResponse struct {
	XorMappedAddress      string  `json:"xor_mapped_address,omitempty"`
	MappedAddress         string  `json:"mapped_address,omitempty"`
	OtherAddress          string  `json:"other_address,omitempty"`
	ResponseOriginAddress string  `json:"response_origin_address,omitempty"`
	Software              string  `json:"Software,omitempty"`
	Mapping               NatType `json:"mapping,omitempty"`
	Filtering             NatType `json:"filtering,omitempty"`
}

type RequestProtocol struct {
	Http        *HttpTest    `json:"http,omitempty"`
	Dns         *DnsTest     `json:"dns,omitempty"`
	DnsOverQuic *DnsOverQuic `json:"dns_over_quic,omitempty"`
	Ip          *Ip          `json:"ip,omitempty"`
	Stun        *Stun        `json:"stun,omitempty"`
}

type Request struct {
	Id     string           `json:"id,omitempty"`
	Hash   string           `json:"hash,omitempty"`
	Ipv6   bool             `json:"ipv6,omitempty"`
	Method *RequestProtocol `json:"method,omitempty"`
}

type Requests struct {
	Requests []*Request `json:"requests,omitempty"`
}

type Response struct {
	IdLatencyMap map[string]*Reply `json:"id_latency_map,omitempty"`
}

type Reply struct {
	Latency string        `json:"latency,omitempty"`
	Ip      *IpResponse   `json:"ip,omitempty"`
	Stun    *StunResponse `json:"stun,omitempty"`
	Error   *Error        `json:"error,omitempty"`
}
