package node

import (
	"time"
)

type HttpTest struct {
	Url string `json:"url"`
}

type DnsTest struct {
	Host         string `json:"host"`
	TargetDomain string `json:"target_name"`
}

type DnsOverQuic struct {
	Host         string `json:"host"`
	TargetDomain string `json:"target_name"`
}

type Ip struct {
	Url       string `json:"url"`
	UserAgent string `json:"user_agent"`
}

type IpResponse struct {
	Ipv4 string `json:"ipv4"`
	Ipv6 string `json:"ipv6"`
}

type Error struct {
	Msg string `json:"msg"`
}

type Stun struct {
	Host string `json:"host"`
	Tcp  bool   `json:"tcp"`
}

type NatType int32

const (
	NatTypeUnknown                      NatType = 0
	NatTypeNoResult                     NatType = 1
	NatTypeEndpointIndependentNoNAT    NatType = 2
	NatTypeEndpointIndependent           NatType = 3
	NatTypeAddressDependent              NatType = 4
	NatTypeAddressAndPortDependent      NatType = 5
	NatTypeServerNotSupportChangePort NatType = 6
)

type StunResponse struct {
	XorMappedAddress      string  `json:"xor_mapped_address"`
	MappedAddress         string  `json:"mapped_address"`
	OtherAddress          string  `json:"other_address"`
	ResponseOriginAddress string  `json:"response_origin_address"`
	Software              string  `json:"Software"`
	Mapping               NatType `json:"mapping"`
	Filtering             NatType `json:"filtering"`
}

type Request struct {
	Id     string          `json:"id"`
	Hash   string          `json:"hash"`
	Ipv6   bool            `json:"ipv6"`
	Method LatencyProtocol `json:"method"`
}

type LatencyProtocolType int32

const (
	LatencyProtocolTypeHttp        LatencyProtocolType = 0
	LatencyProtocolTypeDns         LatencyProtocolType = 1
	LatencyProtocolTypeDnsOverQuic LatencyProtocolType = 2
	LatencyProtocolTypeIp          LatencyProtocolType = 3
	LatencyProtocolTypeStun        LatencyProtocolType = 4
)

type LatencyProtocol struct {
	Type        LatencyProtocolType `json:"type"`
	Http        *HttpTest           `json:"http,omitempty"`
	Dns         *DnsTest            `json:"dns,omitempty"`
	DnsOverQuic *DnsOverQuic        `json:"dns_over_quic,omitempty"`
	Ip          *Ip                 `json:"ip,omitempty"`
	Stun        *Stun               `json:"stun,omitempty"`
}

type Requests struct {
	Requests []Request `json:"requests"`
}

type Response struct {
	IdLatencyMap map[string]Reply `json:"id_latency_map"`
}

type ReplyType int32

const (
	ReplyTypeLatency ReplyType = 0
	ReplyTypeIp      ReplyType = 1
	ReplyTypeStun    ReplyType = 2
	ReplyTypeError   ReplyType = 3
)

type Reply struct {
	Type    ReplyType     `json:"type"`
	Latency time.Duration `json:"latency,omitempty"`
	Ip      *IpResponse   `json:"ip,omitempty"`
	Stun    *StunResponse `json:"stun,omitempty"`
	Error   *Error        `json:"error,omitempty"`
}
