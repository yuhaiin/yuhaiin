// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.3
// 	protoc        v5.29.2
// source: config/dns/dns.proto

package dns

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/gofeaturespb"
	reflect "reflect"
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
	state                       protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Server           *string                `protobuf:"bytes,4,opt,name=server"`
	xxx_hidden_Fakedns          bool                   `protobuf:"varint,5,opt,name=fakedns"`
	xxx_hidden_FakednsIpRange   *string                `protobuf:"bytes,6,opt,name=fakedns_ip_range"`
	xxx_hidden_FakednsIpv6Range *string                `protobuf:"bytes,13,opt,name=fakedns_ipv6_range"`
	xxx_hidden_FakednsWhitelist []string               `protobuf:"bytes,9,rep,name=fakedns_whitelist"`
	xxx_hidden_Hosts            map[string]string      `protobuf:"bytes,8,rep,name=hosts" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	xxx_hidden_Resolver         map[string]*Dns        `protobuf:"bytes,10,rep,name=resolver" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	XXX_raceDetectHookData      protoimpl.RaceDetectHookData
	XXX_presence                [1]uint32
	unknownFields               protoimpl.UnknownFields
	sizeCache                   protoimpl.SizeCache
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
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 7)
}

func (x *DnsConfig) SetFakedns(v bool) {
	x.xxx_hidden_Fakedns = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 7)
}

func (x *DnsConfig) SetFakednsIpRange(v string) {
	x.xxx_hidden_FakednsIpRange = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 7)
}

func (x *DnsConfig) SetFakednsIpv6Range(v string) {
	x.xxx_hidden_FakednsIpv6Range = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 3, 7)
}

func (x *DnsConfig) SetFakednsWhitelist(v []string) {
	x.xxx_hidden_FakednsWhitelist = v
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

	Server           *string
	Fakedns          *bool
	FakednsIpRange   *string
	FakednsIpv6Range *string
	FakednsWhitelist []string
	Hosts            map[string]string
	Resolver         map[string]*Dns
}

func (b0 DnsConfig_builder) Build() *DnsConfig {
	m0 := &DnsConfig{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Server != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 7)
		x.xxx_hidden_Server = b.Server
	}
	if b.Fakedns != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 7)
		x.xxx_hidden_Fakedns = *b.Fakedns
	}
	if b.FakednsIpRange != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 7)
		x.xxx_hidden_FakednsIpRange = b.FakednsIpRange
	}
	if b.FakednsIpv6Range != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 3, 7)
		x.xxx_hidden_FakednsIpv6Range = b.FakednsIpv6Range
	}
	x.xxx_hidden_FakednsWhitelist = b.FakednsWhitelist
	x.xxx_hidden_Hosts = b.Hosts
	x.xxx_hidden_Resolver = b.Resolver
	return m0
}

type FakednsConfig struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Enabled     bool                   `protobuf:"varint,1,opt,name=enabled"`
	xxx_hidden_Ipv4Range   *string                `protobuf:"bytes,2,opt,name=ipv4_range"`
	xxx_hidden_Ipv6Range   *string                `protobuf:"bytes,3,opt,name=ipv6_range"`
	xxx_hidden_Whitelist   []string               `protobuf:"bytes,4,rep,name=whitelist"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
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

func (x *FakednsConfig) SetEnabled(v bool) {
	x.xxx_hidden_Enabled = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 4)
}

func (x *FakednsConfig) SetIpv4Range(v string) {
	x.xxx_hidden_Ipv4Range = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 4)
}

func (x *FakednsConfig) SetIpv6Range(v string) {
	x.xxx_hidden_Ipv6Range = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 4)
}

func (x *FakednsConfig) SetWhitelist(v []string) {
	x.xxx_hidden_Whitelist = v
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

	Enabled   *bool
	Ipv4Range *string
	Ipv6Range *string
	Whitelist []string
}

func (b0 FakednsConfig_builder) Build() *FakednsConfig {
	m0 := &FakednsConfig{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Enabled != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 4)
		x.xxx_hidden_Enabled = *b.Enabled
	}
	if b.Ipv4Range != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 4)
		x.xxx_hidden_Ipv4Range = b.Ipv4Range
	}
	if b.Ipv6Range != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 4)
		x.xxx_hidden_Ipv6Range = b.Ipv6Range
	}
	x.xxx_hidden_Whitelist = b.Whitelist
	return m0
}

var File_config_dns_dns_proto protoreflect.FileDescriptor

var file_config_dns_dns_proto_rawDesc = []byte{
	0x0a, 0x14, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x64, 0x6e, 0x73, 0x2f, 0x64, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x64, 0x6e, 0x73, 0x1a, 0x21, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x67, 0x6f, 0x5f, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x80, 0x01, 0x0a, 0x03, 0x64, 0x6e, 0x73, 0x12, 0x12,
	0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f,
	0x73, 0x74, 0x12, 0x25, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x11, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x75, 0x62,
	0x6e, 0x65, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x75, 0x62, 0x6e, 0x65,
	0x74, 0x12, 0x26, 0x0a, 0x0e, 0x74, 0x6c, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x6c, 0x73, 0x5f, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x96, 0x04, 0x0a, 0x0a, 0x64, 0x6e,
	0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x12, 0x18, 0x0a, 0x07, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x07, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x12, 0x2a, 0x0a, 0x10, 0x66, 0x61,
	0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x69, 0x70, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x69, 0x70,
	0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x2e, 0x0a, 0x12, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e,
	0x73, 0x5f, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x0d, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x12, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x69, 0x70, 0x76, 0x36,
	0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x2c, 0x0a, 0x11, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e,
	0x73, 0x5f, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x09, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x11, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x74, 0x65,
	0x6c, 0x69, 0x73, 0x74, 0x12, 0x38, 0x0a, 0x05, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x08, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e,
	0x73, 0x2e, 0x64, 0x6e, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x48, 0x6f, 0x73,
	0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x05, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x12, 0x41,
	0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x25, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64,
	0x6e, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x6c, 0x76,
	0x65, 0x72, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65,
	0x72, 0x1a, 0x38, 0x0a, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x4d, 0x0a, 0x0d, 0x52,
	0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x26,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64, 0x6e, 0x73, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x4a, 0x04, 0x08, 0x07, 0x10, 0x08,
	0x4a, 0x04, 0x08, 0x01, 0x10, 0x02, 0x4a, 0x04, 0x08, 0x02, 0x10, 0x03, 0x4a, 0x04, 0x08, 0x03,
	0x10, 0x04, 0x52, 0x14, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x5f, 0x72, 0x65, 0x6d, 0x6f,
	0x74, 0x65, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x52, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x52,
	0x06, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x52, 0x09, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72,
	0x61, 0x70, 0x22, 0x88, 0x01, 0x0a, 0x0e, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12,
	0x1e, 0x0a, 0x0a, 0x69, 0x70, 0x76, 0x34, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x70, 0x76, 0x34, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x12,
	0x1e, 0x0a, 0x0a, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x12,
	0x1c, 0x0a, 0x09, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x09, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x2a, 0x4a, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x75, 0x64, 0x70, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x74,
	0x63, 0x70, 0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x64, 0x6f, 0x68, 0x10, 0x03, 0x12, 0x07, 0x0a,
	0x03, 0x64, 0x6f, 0x74, 0x10, 0x04, 0x12, 0x07, 0x0a, 0x03, 0x64, 0x6f, 0x71, 0x10, 0x05, 0x12,
	0x08, 0x0a, 0x04, 0x64, 0x6f, 0x68, 0x33, 0x10, 0x06, 0x42, 0x3c, 0x5a, 0x32, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66,
	0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x64, 0x6e, 0x73, 0x92,
	0x03, 0x05, 0xd2, 0x3e, 0x02, 0x10, 0x03, 0x62, 0x08, 0x65, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x70, 0xe8, 0x07,
}

var file_config_dns_dns_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_config_dns_dns_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_config_dns_dns_proto_goTypes = []any{
	(Type)(0),             // 0: yuhaiin.dns.type
	(*Dns)(nil),           // 1: yuhaiin.dns.dns
	(*DnsConfig)(nil),     // 2: yuhaiin.dns.dns_config
	(*FakednsConfig)(nil), // 3: yuhaiin.dns.fakedns_config
	nil,                   // 4: yuhaiin.dns.dns_config.HostsEntry
	nil,                   // 5: yuhaiin.dns.dns_config.ResolverEntry
}
var file_config_dns_dns_proto_depIdxs = []int32{
	0, // 0: yuhaiin.dns.dns.type:type_name -> yuhaiin.dns.type
	4, // 1: yuhaiin.dns.dns_config.hosts:type_name -> yuhaiin.dns.dns_config.HostsEntry
	5, // 2: yuhaiin.dns.dns_config.resolver:type_name -> yuhaiin.dns.dns_config.ResolverEntry
	1, // 3: yuhaiin.dns.dns_config.ResolverEntry.value:type_name -> yuhaiin.dns.dns
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
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
			RawDescriptor: file_config_dns_dns_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_dns_dns_proto_goTypes,
		DependencyIndexes: file_config_dns_dns_proto_depIdxs,
		EnumInfos:         file_config_dns_dns_proto_enumTypes,
		MessageInfos:      file_config_dns_dns_proto_msgTypes,
	}.Build()
	File_config_dns_dns_proto = out.File
	file_config_dns_dns_proto_rawDesc = nil
	file_config_dns_dns_proto_goTypes = nil
	file_config_dns_dns_proto_depIdxs = nil
}
