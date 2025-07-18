// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: config/dns/dns.proto

package dns

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/gofeaturespb"
	reflect "reflect"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Type int32

const (
	Type_reserve Type = 0
	Type_udp     Type = 1
	Type_tcp     Type = 2
	Type_doh     Type = 3
	Type_dot     Type = 4
	Type_doq     Type = 5
	Type_doh3    Type = 6
)

// Enum value maps for Type.
var (
	Type_name = map[int32]string{
		0: "reserve",
		1: "udp",
		2: "tcp",
		3: "doh",
		4: "dot",
		5: "doq",
		6: "doh3",
	}
	Type_value = map[string]int32{
		"reserve": 0,
		"udp":     1,
		"tcp":     2,
		"doh":     3,
		"dot":     4,
		"doq":     5,
		"doh3":    6,
	}
)

func (x Type) Enum() *Type {
	p := new(Type)
	*p = x
	return p
}

func (x Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Type) Descriptor() protoreflect.EnumDescriptor {
	return file_config_dns_dns_proto_enumTypes[0].Descriptor()
}

func (Type) Type() protoreflect.EnumType {
	return &file_config_dns_dns_proto_enumTypes[0]
}

func (x Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

type Dns struct {
	state                    protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Host          *string                `protobuf:"bytes,1,opt,name=host"`
	xxx_hidden_Type          Type                   `protobuf:"varint,5,opt,name=type,enum=yuhaiin.dns.Type"`
	xxx_hidden_Subnet        *string                `protobuf:"bytes,4,opt,name=subnet"`
	xxx_hidden_TlsServername *string                `protobuf:"bytes,2,opt,name=tls_servername"`
	XXX_raceDetectHookData   protoimpl.RaceDetectHookData
	XXX_presence             [1]uint32
	unknownFields            protoimpl.UnknownFields
	sizeCache                protoimpl.SizeCache
}

func (x *Dns) Reset() {
	*x = Dns{}
	mi := &file_config_dns_dns_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Dns) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dns) ProtoMessage() {}

func (x *Dns) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Dns) GetHost() string {
	if x != nil {
		if x.xxx_hidden_Host != nil {
			return *x.xxx_hidden_Host
		}
		return ""
	}
	return ""
}

func (x *Dns) GetType() Type {
	if x != nil {
		if protoimpl.X.Present(&(x.XXX_presence[0]), 1) {
			return x.xxx_hidden_Type
		}
	}
	return Type_reserve
}

func (x *Dns) GetSubnet() string {
	if x != nil {
		if x.xxx_hidden_Subnet != nil {
			return *x.xxx_hidden_Subnet
		}
		return ""
	}
	return ""
}

func (x *Dns) GetTlsServername() string {
	if x != nil {
		if x.xxx_hidden_TlsServername != nil {
			return *x.xxx_hidden_TlsServername
		}
		return ""
	}
	return ""
}

func (x *Dns) SetHost(v string) {
	x.xxx_hidden_Host = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 4)
}

func (x *Dns) SetType(v Type) {
	x.xxx_hidden_Type = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 4)
}

func (x *Dns) SetSubnet(v string) {
	x.xxx_hidden_Subnet = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 4)
}

func (x *Dns) SetTlsServername(v string) {
	x.xxx_hidden_TlsServername = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 3, 4)
}

func (x *Dns) HasHost() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Dns) HasType() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *Dns) HasSubnet() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 2)
}

func (x *Dns) HasTlsServername() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 3)
}

func (x *Dns) ClearHost() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Host = nil
}

func (x *Dns) ClearType() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Type = Type_reserve
}

func (x *Dns) ClearSubnet() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 2)
	x.xxx_hidden_Subnet = nil
}

func (x *Dns) ClearTlsServername() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 3)
	x.xxx_hidden_TlsServername = nil
}

type Dns_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Host          *string
	Type          *Type
	Subnet        *string
	TlsServername *string
}

func (b0 Dns_builder) Build() *Dns {
	m0 := &Dns{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Host != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 4)
		x.xxx_hidden_Host = b.Host
	}
	if b.Type != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 4)
		x.xxx_hidden_Type = *b.Type
	}
	if b.Subnet != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 4)
		x.xxx_hidden_Subnet = b.Subnet
	}
	if b.TlsServername != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 3, 4)
		x.xxx_hidden_TlsServername = b.TlsServername
	}
	return m0
}

type DnsConfig struct {
	state                           protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Server               *string                `protobuf:"bytes,4,opt,name=server"`
	xxx_hidden_Fakedns              bool                   `protobuf:"varint,5,opt,name=fakedns"`
	xxx_hidden_FakednsIpRange       *string                `protobuf:"bytes,6,opt,name=fakedns_ip_range"`
	xxx_hidden_FakednsIpv6Range     *string                `protobuf:"bytes,13,opt,name=fakedns_ipv6_range"`
	xxx_hidden_FakednsWhitelist     []string               `protobuf:"bytes,9,rep,name=fakedns_whitelist"`
	xxx_hidden_FakednsSkipCheckList []string               `protobuf:"bytes,14,rep,name=fakedns_skip_check_list"`
	xxx_hidden_Hosts                map[string]string      `protobuf:"bytes,8,rep,name=hosts" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	xxx_hidden_Resolver             map[string]*Dns        `protobuf:"bytes,10,rep,name=resolver" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	XXX_raceDetectHookData          protoimpl.RaceDetectHookData
	XXX_presence                    [1]uint32
	unknownFields                   protoimpl.UnknownFields
	sizeCache                       protoimpl.SizeCache
}

func (x *DnsConfig) Reset() {
	*x = DnsConfig{}
	mi := &file_config_dns_dns_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DnsConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsConfig) ProtoMessage() {}

func (x *DnsConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *DnsConfig) GetServer() string {
	if x != nil {
		if x.xxx_hidden_Server != nil {
			return *x.xxx_hidden_Server
		}
		return ""
	}
	return ""
}

func (x *DnsConfig) GetFakedns() bool {
	if x != nil {
		return x.xxx_hidden_Fakedns
	}
	return false
}

func (x *DnsConfig) GetFakednsIpRange() string {
	if x != nil {
		if x.xxx_hidden_FakednsIpRange != nil {
			return *x.xxx_hidden_FakednsIpRange
		}
		return ""
	}
	return ""
}

func (x *DnsConfig) GetFakednsIpv6Range() string {
	if x != nil {
		if x.xxx_hidden_FakednsIpv6Range != nil {
			return *x.xxx_hidden_FakednsIpv6Range
		}
		return ""
	}
	return ""
}

func (x *DnsConfig) GetFakednsWhitelist() []string {
	if x != nil {
		return x.xxx_hidden_FakednsWhitelist
	}
	return nil
}

func (x *DnsConfig) GetFakednsSkipCheckList() []string {
	if x != nil {
		return x.xxx_hidden_FakednsSkipCheckList
	}
	return nil
}

func (x *DnsConfig) GetHosts() map[string]string {
	if x != nil {
		return x.xxx_hidden_Hosts
	}
	return nil
}

func (x *DnsConfig) GetResolver() map[string]*Dns {
	if x != nil {
		return x.xxx_hidden_Resolver
	}
	return nil
}

func (x *DnsConfig) SetServer(v string) {
	x.xxx_hidden_Server = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 8)
}

func (x *DnsConfig) SetFakedns(v bool) {
	x.xxx_hidden_Fakedns = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 8)
}

func (x *DnsConfig) SetFakednsIpRange(v string) {
	x.xxx_hidden_FakednsIpRange = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 8)
}

func (x *DnsConfig) SetFakednsIpv6Range(v string) {
	x.xxx_hidden_FakednsIpv6Range = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 3, 8)
}

func (x *DnsConfig) SetFakednsWhitelist(v []string) {
	x.xxx_hidden_FakednsWhitelist = v
}

func (x *DnsConfig) SetFakednsSkipCheckList(v []string) {
	x.xxx_hidden_FakednsSkipCheckList = v
}

func (x *DnsConfig) SetHosts(v map[string]string) {
	x.xxx_hidden_Hosts = v
}

func (x *DnsConfig) SetResolver(v map[string]*Dns) {
	x.xxx_hidden_Resolver = v
}

func (x *DnsConfig) HasServer() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *DnsConfig) HasFakedns() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *DnsConfig) HasFakednsIpRange() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 2)
}

func (x *DnsConfig) HasFakednsIpv6Range() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 3)
}

func (x *DnsConfig) ClearServer() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Server = nil
}

func (x *DnsConfig) ClearFakedns() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Fakedns = false
}

func (x *DnsConfig) ClearFakednsIpRange() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 2)
	x.xxx_hidden_FakednsIpRange = nil
}

func (x *DnsConfig) ClearFakednsIpv6Range() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 3)
	x.xxx_hidden_FakednsIpv6Range = nil
}

type DnsConfig_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Server               *string
	Fakedns              *bool
	FakednsIpRange       *string
	FakednsIpv6Range     *string
	FakednsWhitelist     []string
	FakednsSkipCheckList []string
	Hosts                map[string]string
	Resolver             map[string]*Dns
}

func (b0 DnsConfig_builder) Build() *DnsConfig {
	m0 := &DnsConfig{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Server != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 8)
		x.xxx_hidden_Server = b.Server
	}
	if b.Fakedns != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 8)
		x.xxx_hidden_Fakedns = *b.Fakedns
	}
	if b.FakednsIpRange != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 8)
		x.xxx_hidden_FakednsIpRange = b.FakednsIpRange
	}
	if b.FakednsIpv6Range != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 3, 8)
		x.xxx_hidden_FakednsIpv6Range = b.FakednsIpv6Range
	}
	x.xxx_hidden_FakednsWhitelist = b.FakednsWhitelist
	x.xxx_hidden_FakednsSkipCheckList = b.FakednsSkipCheckList
	x.xxx_hidden_Hosts = b.Hosts
	x.xxx_hidden_Resolver = b.Resolver
	return m0
}

type FakednsConfig struct {
	state                    protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Enabled       bool                   `protobuf:"varint,1,opt,name=enabled"`
	xxx_hidden_Ipv4Range     *string                `protobuf:"bytes,2,opt,name=ipv4_range"`
	xxx_hidden_Ipv6Range     *string                `protobuf:"bytes,3,opt,name=ipv6_range"`
	xxx_hidden_Whitelist     []string               `protobuf:"bytes,4,rep,name=whitelist"`
	xxx_hidden_SkipCheckList []string               `protobuf:"bytes,5,rep,name=skip_check_list"`
	XXX_raceDetectHookData   protoimpl.RaceDetectHookData
	XXX_presence             [1]uint32
	unknownFields            protoimpl.UnknownFields
	sizeCache                protoimpl.SizeCache
}

func (x *FakednsConfig) Reset() {
	*x = FakednsConfig{}
	mi := &file_config_dns_dns_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FakednsConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FakednsConfig) ProtoMessage() {}

func (x *FakednsConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *FakednsConfig) GetEnabled() bool {
	if x != nil {
		return x.xxx_hidden_Enabled
	}
	return false
}

func (x *FakednsConfig) GetIpv4Range() string {
	if x != nil {
		if x.xxx_hidden_Ipv4Range != nil {
			return *x.xxx_hidden_Ipv4Range
		}
		return ""
	}
	return ""
}

func (x *FakednsConfig) GetIpv6Range() string {
	if x != nil {
		if x.xxx_hidden_Ipv6Range != nil {
			return *x.xxx_hidden_Ipv6Range
		}
		return ""
	}
	return ""
}

func (x *FakednsConfig) GetWhitelist() []string {
	if x != nil {
		return x.xxx_hidden_Whitelist
	}
	return nil
}

func (x *FakednsConfig) GetSkipCheckList() []string {
	if x != nil {
		return x.xxx_hidden_SkipCheckList
	}
	return nil
}

func (x *FakednsConfig) SetEnabled(v bool) {
	x.xxx_hidden_Enabled = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 5)
}

func (x *FakednsConfig) SetIpv4Range(v string) {
	x.xxx_hidden_Ipv4Range = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 5)
}

func (x *FakednsConfig) SetIpv6Range(v string) {
	x.xxx_hidden_Ipv6Range = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 5)
}

func (x *FakednsConfig) SetWhitelist(v []string) {
	x.xxx_hidden_Whitelist = v
}

func (x *FakednsConfig) SetSkipCheckList(v []string) {
	x.xxx_hidden_SkipCheckList = v
}

func (x *FakednsConfig) HasEnabled() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *FakednsConfig) HasIpv4Range() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *FakednsConfig) HasIpv6Range() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 2)
}

func (x *FakednsConfig) ClearEnabled() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Enabled = false
}

func (x *FakednsConfig) ClearIpv4Range() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Ipv4Range = nil
}

func (x *FakednsConfig) ClearIpv6Range() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 2)
	x.xxx_hidden_Ipv6Range = nil
}

type FakednsConfig_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Enabled       *bool
	Ipv4Range     *string
	Ipv6Range     *string
	Whitelist     []string
	SkipCheckList []string
}

func (b0 FakednsConfig_builder) Build() *FakednsConfig {
	m0 := &FakednsConfig{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Enabled != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 5)
		x.xxx_hidden_Enabled = *b.Enabled
	}
	if b.Ipv4Range != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 5)
		x.xxx_hidden_Ipv4Range = b.Ipv4Range
	}
	if b.Ipv6Range != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 5)
		x.xxx_hidden_Ipv6Range = b.Ipv6Range
	}
	x.xxx_hidden_Whitelist = b.Whitelist
	x.xxx_hidden_SkipCheckList = b.SkipCheckList
	return m0
}

type Server struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Host        *string                `protobuf:"bytes,1,opt,name=host"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *Server) Reset() {
	*x = Server{}
	mi := &file_config_dns_dns_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Server) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Server) ProtoMessage() {}

func (x *Server) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Server) GetHost() string {
	if x != nil {
		if x.xxx_hidden_Host != nil {
			return *x.xxx_hidden_Host
		}
		return ""
	}
	return ""
}

func (x *Server) SetHost(v string) {
	x.xxx_hidden_Host = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 1)
}

func (x *Server) HasHost() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Server) ClearHost() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Host = nil
}

type Server_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Host *string
}

func (b0 Server_builder) Build() *Server {
	m0 := &Server{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Host != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 1)
		x.xxx_hidden_Host = b.Host
	}
	return m0
}

type DnsConfigV2 struct {
	state               protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Server   *Server                `protobuf:"bytes,1,opt,name=server"`
	xxx_hidden_Fakedns  *FakednsConfig         `protobuf:"bytes,2,opt,name=fakedns"`
	xxx_hidden_Hosts    map[string]string      `protobuf:"bytes,3,rep,name=hosts" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	xxx_hidden_Resolver map[string]*Dns        `protobuf:"bytes,4,rep,name=resolver" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields       protoimpl.UnknownFields
	sizeCache           protoimpl.SizeCache
}

func (x *DnsConfigV2) Reset() {
	*x = DnsConfigV2{}
	mi := &file_config_dns_dns_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DnsConfigV2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsConfigV2) ProtoMessage() {}

func (x *DnsConfigV2) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *DnsConfigV2) GetServer() *Server {
	if x != nil {
		return x.xxx_hidden_Server
	}
	return nil
}

func (x *DnsConfigV2) GetFakedns() *FakednsConfig {
	if x != nil {
		return x.xxx_hidden_Fakedns
	}
	return nil
}

func (x *DnsConfigV2) GetHosts() map[string]string {
	if x != nil {
		return x.xxx_hidden_Hosts
	}
	return nil
}

func (x *DnsConfigV2) GetResolver() map[string]*Dns {
	if x != nil {
		return x.xxx_hidden_Resolver
	}
	return nil
}

func (x *DnsConfigV2) SetServer(v *Server) {
	x.xxx_hidden_Server = v
}

func (x *DnsConfigV2) SetFakedns(v *FakednsConfig) {
	x.xxx_hidden_Fakedns = v
}

func (x *DnsConfigV2) SetHosts(v map[string]string) {
	x.xxx_hidden_Hosts = v
}

func (x *DnsConfigV2) SetResolver(v map[string]*Dns) {
	x.xxx_hidden_Resolver = v
}

func (x *DnsConfigV2) HasServer() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Server != nil
}

func (x *DnsConfigV2) HasFakedns() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Fakedns != nil
}

func (x *DnsConfigV2) ClearServer() {
	x.xxx_hidden_Server = nil
}

func (x *DnsConfigV2) ClearFakedns() {
	x.xxx_hidden_Fakedns = nil
}

type DnsConfigV2_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Server   *Server
	Fakedns  *FakednsConfig
	Hosts    map[string]string
	Resolver map[string]*Dns
}

func (b0 DnsConfigV2_builder) Build() *DnsConfigV2 {
	m0 := &DnsConfigV2{}
	b, x := &b0, m0
	_, _ = b, x
	x.xxx_hidden_Server = b.Server
	x.xxx_hidden_Fakedns = b.Fakedns
	x.xxx_hidden_Hosts = b.Hosts
	x.xxx_hidden_Resolver = b.Resolver
	return m0
}

var File_config_dns_dns_proto protoreflect.FileDescriptor

const file_config_dns_dns_proto_rawDesc = "" +
	"\n" +
	"\x14config/dns/dns.proto\x12\vyuhaiin.dns\x1a!google/protobuf/go_features.proto\"\x80\x01\n" +
	"\x03dns\x12\x12\n" +
	"\x04host\x18\x01 \x01(\tR\x04host\x12%\n" +
	"\x04type\x18\x05 \x01(\x0e2\x11.yuhaiin.dns.typeR\x04type\x12\x16\n" +
	"\x06subnet\x18\x04 \x01(\tR\x06subnet\x12&\n" +
	"\x0etls_servername\x18\x02 \x01(\tR\x0etls_servername\"\xd0\x04\n" +
	"\n" +
	"dns_config\x12\x16\n" +
	"\x06server\x18\x04 \x01(\tR\x06server\x12\x18\n" +
	"\afakedns\x18\x05 \x01(\bR\afakedns\x12*\n" +
	"\x10fakedns_ip_range\x18\x06 \x01(\tR\x10fakedns_ip_range\x12.\n" +
	"\x12fakedns_ipv6_range\x18\r \x01(\tR\x12fakedns_ipv6_range\x12,\n" +
	"\x11fakedns_whitelist\x18\t \x03(\tR\x11fakedns_whitelist\x128\n" +
	"\x17fakedns_skip_check_list\x18\x0e \x03(\tR\x17fakedns_skip_check_list\x128\n" +
	"\x05hosts\x18\b \x03(\v2\".yuhaiin.dns.dns_config.HostsEntryR\x05hosts\x12A\n" +
	"\bresolver\x18\n" +
	" \x03(\v2%.yuhaiin.dns.dns_config.ResolverEntryR\bresolver\x1a8\n" +
	"\n" +
	"HostsEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\x1aM\n" +
	"\rResolverEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12&\n" +
	"\x05value\x18\x02 \x01(\v2\x10.yuhaiin.dns.dnsR\x05value:\x028\x01J\x04\b\a\x10\bJ\x04\b\x01\x10\x02J\x04\b\x02\x10\x03J\x04\b\x03\x10\x04R\x14resolve_remote_domaiR\x05localR\x06remoteR\tbootstrap\"\xb2\x01\n" +
	"\x0efakedns_config\x12\x18\n" +
	"\aenabled\x18\x01 \x01(\bR\aenabled\x12\x1e\n" +
	"\n" +
	"ipv4_range\x18\x02 \x01(\tR\n" +
	"ipv4_range\x12\x1e\n" +
	"\n" +
	"ipv6_range\x18\x03 \x01(\tR\n" +
	"ipv6_range\x12\x1c\n" +
	"\twhitelist\x18\x04 \x03(\tR\twhitelist\x12(\n" +
	"\x0fskip_check_list\x18\x05 \x03(\tR\x0fskip_check_list\"\x1c\n" +
	"\x06server\x12\x12\n" +
	"\x04host\x18\x01 \x01(\tR\x04host\"\xff\x02\n" +
	"\rdns_config_v2\x12+\n" +
	"\x06server\x18\x01 \x01(\v2\x13.yuhaiin.dns.serverR\x06server\x125\n" +
	"\afakedns\x18\x02 \x01(\v2\x1b.yuhaiin.dns.fakedns_configR\afakedns\x12;\n" +
	"\x05hosts\x18\x03 \x03(\v2%.yuhaiin.dns.dns_config_v2.HostsEntryR\x05hosts\x12D\n" +
	"\bresolver\x18\x04 \x03(\v2(.yuhaiin.dns.dns_config_v2.ResolverEntryR\bresolver\x1a8\n" +
	"\n" +
	"HostsEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n" +
	"\x05value\x18\x02 \x01(\tR\x05value:\x028\x01\x1aM\n" +
	"\rResolverEntry\x12\x10\n" +
	"\x03key\x18\x01 \x01(\tR\x03key\x12&\n" +
	"\x05value\x18\x02 \x01(\v2\x10.yuhaiin.dns.dnsR\x05value:\x028\x01*J\n" +
	"\x04type\x12\v\n" +
	"\areserve\x10\x00\x12\a\n" +
	"\x03udp\x10\x01\x12\a\n" +
	"\x03tcp\x10\x02\x12\a\n" +
	"\x03doh\x10\x03\x12\a\n" +
	"\x03dot\x10\x04\x12\a\n" +
	"\x03doq\x10\x05\x12\b\n" +
	"\x04doh3\x10\x06B<Z2github.com/Asutorufa/yuhaiin/pkg/protos/config/dns\x92\x03\x05\xd2>\x02\x10\x03b\beditionsp\xe8\a"

var file_config_dns_dns_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_config_dns_dns_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_config_dns_dns_proto_goTypes = []any{
	(Type)(0),             // 0: yuhaiin.dns.type
	(*Dns)(nil),           // 1: yuhaiin.dns.dns
	(*DnsConfig)(nil),     // 2: yuhaiin.dns.dns_config
	(*FakednsConfig)(nil), // 3: yuhaiin.dns.fakedns_config
	(*Server)(nil),        // 4: yuhaiin.dns.server
	(*DnsConfigV2)(nil),   // 5: yuhaiin.dns.dns_config_v2
	nil,                   // 6: yuhaiin.dns.dns_config.HostsEntry
	nil,                   // 7: yuhaiin.dns.dns_config.ResolverEntry
	nil,                   // 8: yuhaiin.dns.dns_config_v2.HostsEntry
	nil,                   // 9: yuhaiin.dns.dns_config_v2.ResolverEntry
}
var file_config_dns_dns_proto_depIdxs = []int32{
	0, // 0: yuhaiin.dns.dns.type:type_name -> yuhaiin.dns.type
	6, // 1: yuhaiin.dns.dns_config.hosts:type_name -> yuhaiin.dns.dns_config.HostsEntry
	7, // 2: yuhaiin.dns.dns_config.resolver:type_name -> yuhaiin.dns.dns_config.ResolverEntry
	4, // 3: yuhaiin.dns.dns_config_v2.server:type_name -> yuhaiin.dns.server
	3, // 4: yuhaiin.dns.dns_config_v2.fakedns:type_name -> yuhaiin.dns.fakedns_config
	8, // 5: yuhaiin.dns.dns_config_v2.hosts:type_name -> yuhaiin.dns.dns_config_v2.HostsEntry
	9, // 6: yuhaiin.dns.dns_config_v2.resolver:type_name -> yuhaiin.dns.dns_config_v2.ResolverEntry
	1, // 7: yuhaiin.dns.dns_config.ResolverEntry.value:type_name -> yuhaiin.dns.dns
	1, // 8: yuhaiin.dns.dns_config_v2.ResolverEntry.value:type_name -> yuhaiin.dns.dns
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_config_dns_dns_proto_init() }
func file_config_dns_dns_proto_init() {
	if File_config_dns_dns_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_config_dns_dns_proto_rawDesc), len(file_config_dns_dns_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_dns_dns_proto_goTypes,
		DependencyIndexes: file_config_dns_dns_proto_depIdxs,
		EnumInfos:         file_config_dns_dns_proto_enumTypes,
		MessageInfos:      file_config_dns_dns_proto_msgTypes,
	}.Build()
	File_config_dns_dns_proto = out.File
	file_config_dns_dns_proto_goTypes = nil
	file_config_dns_dns_proto_depIdxs = nil
}
