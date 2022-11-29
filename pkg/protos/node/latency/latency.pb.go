// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.9
// source: node/latency/latency.proto

package latency

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Http struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Url string `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
}

func (x *Http) Reset() {
	*x = Http{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_latency_latency_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Http) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Http) ProtoMessage() {}

func (x *Http) ProtoReflect() protoreflect.Message {
	mi := &file_node_latency_latency_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Http.ProtoReflect.Descriptor instead.
func (*Http) Descriptor() ([]byte, []int) {
	return file_node_latency_latency_proto_rawDescGZIP(), []int{0}
}

func (x *Http) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

type Dns struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host         string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	TargetDomain string `protobuf:"bytes,2,opt,name=target_domain,json=target_name,proto3" json:"target_domain,omitempty"`
}

func (x *Dns) Reset() {
	*x = Dns{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_latency_latency_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Dns) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dns) ProtoMessage() {}

func (x *Dns) ProtoReflect() protoreflect.Message {
	mi := &file_node_latency_latency_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Dns.ProtoReflect.Descriptor instead.
func (*Dns) Descriptor() ([]byte, []int) {
	return file_node_latency_latency_proto_rawDescGZIP(), []int{1}
}

func (x *Dns) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Dns) GetTargetDomain() string {
	if x != nil {
		return x.TargetDomain
	}
	return ""
}

type DnsOverQuic struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host         string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	TargetDomain string `protobuf:"bytes,2,opt,name=target_domain,json=target_name,proto3" json:"target_domain,omitempty"`
}

func (x *DnsOverQuic) Reset() {
	*x = DnsOverQuic{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_latency_latency_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DnsOverQuic) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsOverQuic) ProtoMessage() {}

func (x *DnsOverQuic) ProtoReflect() protoreflect.Message {
	mi := &file_node_latency_latency_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DnsOverQuic.ProtoReflect.Descriptor instead.
func (*DnsOverQuic) Descriptor() ([]byte, []int) {
	return file_node_latency_latency_proto_rawDescGZIP(), []int{2}
}

func (x *DnsOverQuic) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *DnsOverQuic) GetTargetDomain() string {
	if x != nil {
		return x.TargetDomain
	}
	return ""
}

type Protocol struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Protocol:
	//	*Protocol_Http
	//	*Protocol_Dns
	//	*Protocol_DnsOverQuic
	Protocol isProtocol_Protocol `protobuf_oneof:"protocol"`
}

func (x *Protocol) Reset() {
	*x = Protocol{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_latency_latency_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Protocol) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Protocol) ProtoMessage() {}

func (x *Protocol) ProtoReflect() protoreflect.Message {
	mi := &file_node_latency_latency_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Protocol.ProtoReflect.Descriptor instead.
func (*Protocol) Descriptor() ([]byte, []int) {
	return file_node_latency_latency_proto_rawDescGZIP(), []int{3}
}

func (m *Protocol) GetProtocol() isProtocol_Protocol {
	if m != nil {
		return m.Protocol
	}
	return nil
}

func (x *Protocol) GetHttp() *Http {
	if x, ok := x.GetProtocol().(*Protocol_Http); ok {
		return x.Http
	}
	return nil
}

func (x *Protocol) GetDns() *Dns {
	if x, ok := x.GetProtocol().(*Protocol_Dns); ok {
		return x.Dns
	}
	return nil
}

func (x *Protocol) GetDnsOverQuic() *DnsOverQuic {
	if x, ok := x.GetProtocol().(*Protocol_DnsOverQuic); ok {
		return x.DnsOverQuic
	}
	return nil
}

type isProtocol_Protocol interface {
	isProtocol_Protocol()
}

type Protocol_Http struct {
	Http *Http `protobuf:"bytes,1,opt,name=http,proto3,oneof"`
}

type Protocol_Dns struct {
	Dns *Dns `protobuf:"bytes,2,opt,name=dns,proto3,oneof"`
}

type Protocol_DnsOverQuic struct {
	DnsOverQuic *DnsOverQuic `protobuf:"bytes,3,opt,name=dns_over_quic,proto3,oneof"`
}

func (*Protocol_Http) isProtocol_Protocol() {}

func (*Protocol_Dns) isProtocol_Protocol() {}

func (*Protocol_DnsOverQuic) isProtocol_Protocol() {}

type Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id       string    `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
	Hash     string    `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	Protocol *Protocol `protobuf:"bytes,2,opt,name=protocol,proto3" json:"protocol,omitempty"`
}

func (x *Request) Reset() {
	*x = Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_latency_latency_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request) ProtoMessage() {}

func (x *Request) ProtoReflect() protoreflect.Message {
	mi := &file_node_latency_latency_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request.ProtoReflect.Descriptor instead.
func (*Request) Descriptor() ([]byte, []int) {
	return file_node_latency_latency_proto_rawDescGZIP(), []int{4}
}

func (x *Request) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Request) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

func (x *Request) GetProtocol() *Protocol {
	if x != nil {
		return x.Protocol
	}
	return nil
}

type Requests struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Requests []*Request `protobuf:"bytes,1,rep,name=requests,proto3" json:"requests,omitempty"`
}

func (x *Requests) Reset() {
	*x = Requests{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_latency_latency_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Requests) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Requests) ProtoMessage() {}

func (x *Requests) ProtoReflect() protoreflect.Message {
	mi := &file_node_latency_latency_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Requests.ProtoReflect.Descriptor instead.
func (*Requests) Descriptor() ([]byte, []int) {
	return file_node_latency_latency_proto_rawDescGZIP(), []int{5}
}

func (x *Requests) GetRequests() []*Request {
	if x != nil {
		return x.Requests
	}
	return nil
}

type Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IdLatencyMap map[string]*durationpb.Duration `protobuf:"bytes,1,rep,name=id_latency_map,proto3" json:"id_latency_map,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Response) Reset() {
	*x = Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_latency_latency_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response) ProtoMessage() {}

func (x *Response) ProtoReflect() protoreflect.Message {
	mi := &file_node_latency_latency_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response.ProtoReflect.Descriptor instead.
func (*Response) Descriptor() ([]byte, []int) {
	return file_node_latency_latency_proto_rawDescGZIP(), []int{6}
}

func (x *Response) GetIdLatencyMap() map[string]*durationpb.Duration {
	if x != nil {
		return x.IdLatencyMap
	}
	return nil
}

var File_node_latency_latency_proto protoreflect.FileDescriptor

var file_node_latency_latency_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2f, 0x6c,
	0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x1a, 0x1e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x18, 0x0a,
	0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x22, 0x3d, 0x0a, 0x03, 0x64, 0x6e, 0x73, 0x12, 0x12,
	0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f,
	0x73, 0x74, 0x12, 0x22, 0x0a, 0x0d, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x64, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x47, 0x0a, 0x0d, 0x64, 0x6e, 0x73, 0x5f, 0x6f, 0x76,
	0x65, 0x72, 0x5f, 0x71, 0x75, 0x69, 0x63, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x22, 0x0a, 0x0d, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x22,
	0xb5, 0x01, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x2b, 0x0a, 0x04,
	0x68, 0x74, 0x74, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x68, 0x74, 0x74,
	0x70, 0x48, 0x00, 0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x28, 0x0a, 0x03, 0x64, 0x6e, 0x73,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x64, 0x6e, 0x73, 0x48, 0x00, 0x52, 0x03,
	0x64, 0x6e, 0x73, 0x12, 0x46, 0x0a, 0x0d, 0x64, 0x6e, 0x73, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x5f,
	0x71, 0x75, 0x69, 0x63, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x64, 0x6e, 0x73,
	0x5f, 0x6f, 0x76, 0x65, 0x72, 0x5f, 0x71, 0x75, 0x69, 0x63, 0x48, 0x00, 0x52, 0x0d, 0x64, 0x6e,
	0x73, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x5f, 0x71, 0x75, 0x69, 0x63, 0x42, 0x0a, 0x0a, 0x08, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x22, 0x64, 0x0a, 0x07, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x35, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63,
	0x6f, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x22, 0x40, 0x0a,
	0x08, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x12, 0x34, 0x0a, 0x08, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x08, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x22,
	0xbb, 0x01, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x53, 0x0a, 0x0e,
	0x69, 0x64, 0x5f, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x5f, 0x6d, 0x61, 0x70, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c,
	0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e,
	0x49, 0x64, 0x4c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x0e, 0x69, 0x64, 0x5f, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x5f, 0x6d, 0x61,
	0x70, 0x1a, 0x5a, 0x0a, 0x11, 0x49, 0x64, 0x4c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x4d, 0x61,
	0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2f, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x36, 0x5a,
	0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75, 0x74,
	0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f, 0x70, 0x6b,
	0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x6c, 0x61,
	0x74, 0x65, 0x6e, 0x63, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_node_latency_latency_proto_rawDescOnce sync.Once
	file_node_latency_latency_proto_rawDescData = file_node_latency_latency_proto_rawDesc
)

func file_node_latency_latency_proto_rawDescGZIP() []byte {
	file_node_latency_latency_proto_rawDescOnce.Do(func() {
		file_node_latency_latency_proto_rawDescData = protoimpl.X.CompressGZIP(file_node_latency_latency_proto_rawDescData)
	})
	return file_node_latency_latency_proto_rawDescData
}

var file_node_latency_latency_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_node_latency_latency_proto_goTypes = []interface{}{
	(*Http)(nil),                // 0: yuhaiin.latency.http
	(*Dns)(nil),                 // 1: yuhaiin.latency.dns
	(*DnsOverQuic)(nil),         // 2: yuhaiin.latency.dns_over_quic
	(*Protocol)(nil),            // 3: yuhaiin.latency.protocol
	(*Request)(nil),             // 4: yuhaiin.latency.request
	(*Requests)(nil),            // 5: yuhaiin.latency.requests
	(*Response)(nil),            // 6: yuhaiin.latency.response
	nil,                         // 7: yuhaiin.latency.response.IdLatencyMapEntry
	(*durationpb.Duration)(nil), // 8: google.protobuf.Duration
}
var file_node_latency_latency_proto_depIdxs = []int32{
	0, // 0: yuhaiin.latency.protocol.http:type_name -> yuhaiin.latency.http
	1, // 1: yuhaiin.latency.protocol.dns:type_name -> yuhaiin.latency.dns
	2, // 2: yuhaiin.latency.protocol.dns_over_quic:type_name -> yuhaiin.latency.dns_over_quic
	3, // 3: yuhaiin.latency.request.protocol:type_name -> yuhaiin.latency.protocol
	4, // 4: yuhaiin.latency.requests.requests:type_name -> yuhaiin.latency.request
	7, // 5: yuhaiin.latency.response.id_latency_map:type_name -> yuhaiin.latency.response.IdLatencyMapEntry
	8, // 6: yuhaiin.latency.response.IdLatencyMapEntry.value:type_name -> google.protobuf.Duration
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_node_latency_latency_proto_init() }
func file_node_latency_latency_proto_init() {
	if File_node_latency_latency_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_node_latency_latency_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Http); i {
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
		file_node_latency_latency_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Dns); i {
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
		file_node_latency_latency_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DnsOverQuic); i {
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
		file_node_latency_latency_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Protocol); i {
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
		file_node_latency_latency_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Request); i {
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
		file_node_latency_latency_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Requests); i {
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
		file_node_latency_latency_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Response); i {
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
	file_node_latency_latency_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*Protocol_Http)(nil),
		(*Protocol_Dns)(nil),
		(*Protocol_DnsOverQuic)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_node_latency_latency_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_node_latency_latency_proto_goTypes,
		DependencyIndexes: file_node_latency_latency_proto_depIdxs,
		MessageInfos:      file_node_latency_latency_proto_msgTypes,
	}.Build()
	File_node_latency_latency_proto = out.File
	file_node_latency_latency_proto_rawDesc = nil
	file_node_latency_latency_proto_goTypes = nil
	file_node_latency_latency_proto_depIdxs = nil
}