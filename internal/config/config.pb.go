// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.4
// source: internal/config/config.proto

package config

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type DNSDnsType int32

const (
	DNS_reserve DNSDnsType = 0
	DNS_udp     DNSDnsType = 1
	DNS_tcp     DNSDnsType = 2
	DNS_doh     DNSDnsType = 3
	DNS_dot     DNSDnsType = 4
)

// Enum value maps for DNSDnsType.
var (
	DNSDnsType_name = map[int32]string{
		0: "reserve",
		1: "udp",
		2: "tcp",
		3: "doh",
		4: "dot",
	}
	DNSDnsType_value = map[string]int32{
		"reserve": 0,
		"udp":     1,
		"tcp":     2,
		"doh":     3,
		"dot":     4,
	}
)

func (x DNSDnsType) Enum() *DNSDnsType {
	p := new(DNSDnsType)
	*p = x
	return p
}

func (x DNSDnsType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DNSDnsType) Descriptor() protoreflect.EnumDescriptor {
	return file_internal_config_config_proto_enumTypes[0].Descriptor()
}

func (DNSDnsType) Type() protoreflect.EnumType {
	return &file_internal_config_config_proto_enumTypes[0]
}

func (x DNSDnsType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DNSDnsType.Descriptor instead.
func (DNSDnsType) EnumDescriptor() ([]byte, []int) {
	return file_internal_config_config_proto_rawDescGZIP(), []int{4, 0}
}

type Setting struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SystemProxy *SystemProxy `protobuf:"bytes,1,opt,name=SystemProxy,json=system_proxy,proto3" json:"SystemProxy,omitempty"`
	Bypass      *Bypass      `protobuf:"bytes,2,opt,name=Bypass,json=bypass,proto3" json:"Bypass,omitempty"`
	Proxy       *Proxy       `protobuf:"bytes,3,opt,name=Proxy,json=proxy,proto3" json:"Proxy,omitempty"`
	Dns         *DnsSetting  `protobuf:"bytes,4,opt,name=dns,proto3" json:"dns,omitempty"`
}

func (x *Setting) Reset() {
	*x = Setting{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_config_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Setting) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Setting) ProtoMessage() {}

func (x *Setting) ProtoReflect() protoreflect.Message {
	mi := &file_internal_config_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Setting.ProtoReflect.Descriptor instead.
func (*Setting) Descriptor() ([]byte, []int) {
	return file_internal_config_config_proto_rawDescGZIP(), []int{0}
}

func (x *Setting) GetSystemProxy() *SystemProxy {
	if x != nil {
		return x.SystemProxy
	}
	return nil
}

func (x *Setting) GetBypass() *Bypass {
	if x != nil {
		return x.Bypass
	}
	return nil
}

func (x *Setting) GetProxy() *Proxy {
	if x != nil {
		return x.Proxy
	}
	return nil
}

func (x *Setting) GetDns() *DnsSetting {
	if x != nil {
		return x.Dns
	}
	return nil
}

type DnsSetting struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Remote *DNS `protobuf:"bytes,1,opt,name=remote,proto3" json:"remote,omitempty"`
	Local  *DNS `protobuf:"bytes,2,opt,name=local,proto3" json:"local,omitempty"`
}

func (x *DnsSetting) Reset() {
	*x = DnsSetting{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_config_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DnsSetting) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsSetting) ProtoMessage() {}

func (x *DnsSetting) ProtoReflect() protoreflect.Message {
	mi := &file_internal_config_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DnsSetting.ProtoReflect.Descriptor instead.
func (*DnsSetting) Descriptor() ([]byte, []int) {
	return file_internal_config_config_proto_rawDescGZIP(), []int{1}
}

func (x *DnsSetting) GetRemote() *DNS {
	if x != nil {
		return x.Remote
	}
	return nil
}

func (x *DnsSetting) GetLocal() *DNS {
	if x != nil {
		return x.Local
	}
	return nil
}

type SystemProxy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HTTP   bool `protobuf:"varint,2,opt,name=HTTP,json=http,proto3" json:"HTTP,omitempty"`
	Socks5 bool `protobuf:"varint,3,opt,name=Socks5,json=socks5,proto3" json:"Socks5,omitempty"`
}

func (x *SystemProxy) Reset() {
	*x = SystemProxy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_config_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SystemProxy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SystemProxy) ProtoMessage() {}

func (x *SystemProxy) ProtoReflect() protoreflect.Message {
	mi := &file_internal_config_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SystemProxy.ProtoReflect.Descriptor instead.
func (*SystemProxy) Descriptor() ([]byte, []int) {
	return file_internal_config_config_proto_rawDescGZIP(), []int{2}
}

func (x *SystemProxy) GetHTTP() bool {
	if x != nil {
		return x.HTTP
	}
	return false
}

func (x *SystemProxy) GetSocks5() bool {
	if x != nil {
		return x.Socks5
	}
	return false
}

type Bypass struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Enabled    bool   `protobuf:"varint,1,opt,name=Enabled,json=enabled,proto3" json:"Enabled,omitempty"`
	BypassFile string `protobuf:"bytes,2,opt,name=BypassFile,json=bypass_file,proto3" json:"BypassFile,omitempty"`
}

func (x *Bypass) Reset() {
	*x = Bypass{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_config_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Bypass) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Bypass) ProtoMessage() {}

func (x *Bypass) ProtoReflect() protoreflect.Message {
	mi := &file_internal_config_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Bypass.ProtoReflect.Descriptor instead.
func (*Bypass) Descriptor() ([]byte, []int) {
	return file_internal_config_config_proto_rawDescGZIP(), []int{3}
}

func (x *Bypass) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *Bypass) GetBypassFile() string {
	if x != nil {
		return x.BypassFile
	}
	return ""
}

type DNS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host   string     `protobuf:"bytes,1,opt,name=Host,json=host,proto3" json:"Host,omitempty"`
	Type   DNSDnsType `protobuf:"varint,5,opt,name=type,proto3,enum=yuhaiin.api.DNSDnsType" json:"type,omitempty"`
	Proxy  bool       `protobuf:"varint,3,opt,name=Proxy,json=proxy,proto3" json:"Proxy,omitempty"`
	Subnet string     `protobuf:"bytes,4,opt,name=subnet,proto3" json:"subnet,omitempty"`
}

func (x *DNS) Reset() {
	*x = DNS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_config_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DNS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DNS) ProtoMessage() {}

func (x *DNS) ProtoReflect() protoreflect.Message {
	mi := &file_internal_config_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DNS.ProtoReflect.Descriptor instead.
func (*DNS) Descriptor() ([]byte, []int) {
	return file_internal_config_config_proto_rawDescGZIP(), []int{4}
}

func (x *DNS) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *DNS) GetType() DNSDnsType {
	if x != nil {
		return x.Type
	}
	return DNS_reserve
}

func (x *DNS) GetProxy() bool {
	if x != nil {
		return x.Proxy
	}
	return false
}

func (x *DNS) GetSubnet() string {
	if x != nil {
		return x.Subnet
	}
	return ""
}

type Proxy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HTTP   string `protobuf:"bytes,1,opt,name=HTTP,json=http,proto3" json:"HTTP,omitempty"`
	Socks5 string `protobuf:"bytes,2,opt,name=Socks5,json=socks5,proto3" json:"Socks5,omitempty"`
	Redir  string `protobuf:"bytes,3,opt,name=Redir,json=redir,proto3" json:"Redir,omitempty"`
}

func (x *Proxy) Reset() {
	*x = Proxy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_config_config_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Proxy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Proxy) ProtoMessage() {}

func (x *Proxy) ProtoReflect() protoreflect.Message {
	mi := &file_internal_config_config_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Proxy.ProtoReflect.Descriptor instead.
func (*Proxy) Descriptor() ([]byte, []int) {
	return file_internal_config_config_proto_rawDescGZIP(), []int{5}
}

func (x *Proxy) GetHTTP() string {
	if x != nil {
		return x.HTTP
	}
	return ""
}

func (x *Proxy) GetSocks5() string {
	if x != nil {
		return x.Socks5
	}
	return ""
}

func (x *Proxy) GetRedir() string {
	if x != nil {
		return x.Redir
	}
	return ""
}

var File_internal_config_config_proto protoreflect.FileDescriptor

var file_internal_config_config_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x1a, 0x1b, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70,
	0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc9, 0x01, 0x0a, 0x07, 0x53, 0x65, 0x74,
	0x74, 0x69, 0x6e, 0x67, 0x12, 0x3b, 0x0a, 0x0b, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x50, 0x72,
	0x6f, 0x78, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x79, 0x75, 0x68, 0x61,
	0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x50, 0x72,
	0x6f, 0x78, 0x79, 0x52, 0x0c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x12, 0x2b, 0x0a, 0x06, 0x42, 0x79, 0x70, 0x61, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x13, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x42, 0x79, 0x70, 0x61, 0x73, 0x73, 0x52, 0x06, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x12, 0x28,
	0x0a, 0x05, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x12, 0x2a, 0x0a, 0x03, 0x64, 0x6e, 0x73, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x64, 0x6e, 0x73, 0x5f, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x52,
	0x03, 0x64, 0x6e, 0x73, 0x22, 0x5f, 0x0a, 0x0b, 0x64, 0x6e, 0x73, 0x5f, 0x73, 0x65, 0x74, 0x74,
	0x69, 0x6e, 0x67, 0x12, 0x28, 0x0a, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x44, 0x4e, 0x53, 0x52, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x12, 0x26, 0x0a,
	0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x44, 0x4e, 0x53, 0x52, 0x05,
	0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x22, 0x39, 0x0a, 0x0b, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x50,
	0x72, 0x6f, 0x78, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x54, 0x54, 0x50, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x6f, 0x63, 0x6b,
	0x73, 0x35, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35,
	0x22, 0x43, 0x0a, 0x06, 0x42, 0x79, 0x70, 0x61, 0x73, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x45, 0x6e,
	0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61,
	0x62, 0x6c, 0x65, 0x64, 0x12, 0x1f, 0x0a, 0x0a, 0x42, 0x79, 0x70, 0x61, 0x73, 0x73, 0x46, 0x69,
	0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73,
	0x5f, 0x66, 0x69, 0x6c, 0x65, 0x22, 0xb3, 0x01, 0x0a, 0x03, 0x44, 0x4e, 0x53, 0x12, 0x12, 0x0a,
	0x04, 0x48, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73,
	0x74, 0x12, 0x2d, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x19, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x44, 0x4e,
	0x53, 0x2e, 0x64, 0x6e, 0x73, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x05, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x22, 0x3b,
	0x0a, 0x08, 0x64, 0x6e, 0x73, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x72, 0x65,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x75, 0x64, 0x70, 0x10, 0x01,
	0x12, 0x07, 0x0a, 0x03, 0x74, 0x63, 0x70, 0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x64, 0x6f, 0x68,
	0x10, 0x03, 0x12, 0x07, 0x0a, 0x03, 0x64, 0x6f, 0x74, 0x10, 0x04, 0x22, 0x49, 0x0a, 0x05, 0x50,
	0x72, 0x6f, 0x78, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x54, 0x54, 0x50, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x6f, 0x63, 0x6b,
	0x73, 0x35, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35,
	0x12, 0x14, 0x0a, 0x05, 0x52, 0x65, 0x64, 0x69, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x72, 0x65, 0x64, 0x69, 0x72, 0x32, 0x78, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x5f, 0x64, 0x61, 0x6f, 0x12, 0x34, 0x0a, 0x04, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x16, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45,
	0x6d, 0x70, 0x74, 0x79, 0x1a, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x12, 0x34, 0x0a, 0x04, 0x73, 0x61,
	0x76, 0x65, 0x12, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79,
	0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41,
	0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_internal_config_config_proto_rawDescOnce sync.Once
	file_internal_config_config_proto_rawDescData = file_internal_config_config_proto_rawDesc
)

func file_internal_config_config_proto_rawDescGZIP() []byte {
	file_internal_config_config_proto_rawDescOnce.Do(func() {
		file_internal_config_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_internal_config_config_proto_rawDescData)
	})
	return file_internal_config_config_proto_rawDescData
}

var file_internal_config_config_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_internal_config_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_internal_config_config_proto_goTypes = []interface{}{
	(DNSDnsType)(0),       // 0: yuhaiin.api.DNS.dns_type
	(*Setting)(nil),       // 1: yuhaiin.api.Setting
	(*DnsSetting)(nil),    // 2: yuhaiin.api.dns_setting
	(*SystemProxy)(nil),   // 3: yuhaiin.api.SystemProxy
	(*Bypass)(nil),        // 4: yuhaiin.api.Bypass
	(*DNS)(nil),           // 5: yuhaiin.api.DNS
	(*Proxy)(nil),         // 6: yuhaiin.api.Proxy
	(*emptypb.Empty)(nil), // 7: google.protobuf.Empty
}
var file_internal_config_config_proto_depIdxs = []int32{
	3, // 0: yuhaiin.api.Setting.SystemProxy:type_name -> yuhaiin.api.SystemProxy
	4, // 1: yuhaiin.api.Setting.Bypass:type_name -> yuhaiin.api.Bypass
	6, // 2: yuhaiin.api.Setting.Proxy:type_name -> yuhaiin.api.Proxy
	2, // 3: yuhaiin.api.Setting.dns:type_name -> yuhaiin.api.dns_setting
	5, // 4: yuhaiin.api.dns_setting.remote:type_name -> yuhaiin.api.DNS
	5, // 5: yuhaiin.api.dns_setting.local:type_name -> yuhaiin.api.DNS
	0, // 6: yuhaiin.api.DNS.type:type_name -> yuhaiin.api.DNS.dns_type
	7, // 7: yuhaiin.api.config_dao.load:input_type -> google.protobuf.Empty
	1, // 8: yuhaiin.api.config_dao.save:input_type -> yuhaiin.api.Setting
	1, // 9: yuhaiin.api.config_dao.load:output_type -> yuhaiin.api.Setting
	7, // 10: yuhaiin.api.config_dao.save:output_type -> google.protobuf.Empty
	9, // [9:11] is the sub-list for method output_type
	7, // [7:9] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_internal_config_config_proto_init() }
func file_internal_config_config_proto_init() {
	if File_internal_config_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_internal_config_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Setting); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_config_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DnsSetting); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_config_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SystemProxy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_config_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Bypass); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_config_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DNS); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_config_config_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Proxy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_internal_config_config_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_internal_config_config_proto_goTypes,
		DependencyIndexes: file_internal_config_config_proto_depIdxs,
		EnumInfos:         file_internal_config_config_proto_enumTypes,
		MessageInfos:      file_internal_config_config_proto_msgTypes,
	}.Build()
	File_internal_config_config_proto = out.File
	file_internal_config_config_proto_rawDesc = nil
	file_internal_config_config_proto_goTypes = nil
	file_internal_config_config_proto_depIdxs = nil
}
