// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.2
// source: statistic/grpc/config.proto

package service

import (
	statistic "github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
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

type TotalFlow struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Download uint64 `protobuf:"varint,1,opt,name=download,proto3" json:"download,omitempty"`
	Upload   uint64 `protobuf:"varint,2,opt,name=upload,proto3" json:"upload,omitempty"`
}

func (x *TotalFlow) Reset() {
	*x = TotalFlow{}
	if protoimpl.UnsafeEnabled {
		mi := &file_statistic_grpc_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TotalFlow) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TotalFlow) ProtoMessage() {}

func (x *TotalFlow) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TotalFlow.ProtoReflect.Descriptor instead.
func (*TotalFlow) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{0}
}

func (x *TotalFlow) GetDownload() uint64 {
	if x != nil {
		return x.Download
	}
	return 0
}

func (x *TotalFlow) GetUpload() uint64 {
	if x != nil {
		return x.Upload
	}
	return 0
}

type NotifyData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Data:
	//
	//	*NotifyData_TotalFlow
	//	*NotifyData_NotifyNewConnections
	//	*NotifyData_NotifyRemoveConnections
	Data isNotifyData_Data `protobuf_oneof:"data"`
}

func (x *NotifyData) Reset() {
	*x = NotifyData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_statistic_grpc_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NotifyData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotifyData) ProtoMessage() {}

func (x *NotifyData) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotifyData.ProtoReflect.Descriptor instead.
func (*NotifyData) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{1}
}

func (m *NotifyData) GetData() isNotifyData_Data {
	if m != nil {
		return m.Data
	}
	return nil
}

func (x *NotifyData) GetTotalFlow() *TotalFlow {
	if x, ok := x.GetData().(*NotifyData_TotalFlow); ok {
		return x.TotalFlow
	}
	return nil
}

func (x *NotifyData) GetNotifyNewConnections() *NotifyNewConnections {
	if x, ok := x.GetData().(*NotifyData_NotifyNewConnections); ok {
		return x.NotifyNewConnections
	}
	return nil
}

func (x *NotifyData) GetNotifyRemoveConnections() *NotifyRemoveConnections {
	if x, ok := x.GetData().(*NotifyData_NotifyRemoveConnections); ok {
		return x.NotifyRemoveConnections
	}
	return nil
}

type isNotifyData_Data interface {
	isNotifyData_Data()
}

type NotifyData_TotalFlow struct {
	TotalFlow *TotalFlow `protobuf:"bytes,3,opt,name=total_flow,json=totalFlow,proto3,oneof"`
}

type NotifyData_NotifyNewConnections struct {
	NotifyNewConnections *NotifyNewConnections `protobuf:"bytes,1,opt,name=notify_new_connections,json=notifyNewConnections,proto3,oneof"`
}

type NotifyData_NotifyRemoveConnections struct {
	NotifyRemoveConnections *NotifyRemoveConnections `protobuf:"bytes,2,opt,name=notify_remove_connections,json=notifyRemoveConnections,proto3,oneof"`
}

func (*NotifyData_TotalFlow) isNotifyData_Data() {}

func (*NotifyData_NotifyNewConnections) isNotifyData_Data() {}

func (*NotifyData_NotifyRemoveConnections) isNotifyData_Data() {}

type NotifyNewConnections struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Connections []*statistic.Connection `protobuf:"bytes,1,rep,name=connections,proto3" json:"connections,omitempty"`
}

func (x *NotifyNewConnections) Reset() {
	*x = NotifyNewConnections{}
	if protoimpl.UnsafeEnabled {
		mi := &file_statistic_grpc_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NotifyNewConnections) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotifyNewConnections) ProtoMessage() {}

func (x *NotifyNewConnections) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotifyNewConnections.ProtoReflect.Descriptor instead.
func (*NotifyNewConnections) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{2}
}

func (x *NotifyNewConnections) GetConnections() []*statistic.Connection {
	if x != nil {
		return x.Connections
	}
	return nil
}

type NotifyRemoveConnections struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ids []uint64 `protobuf:"varint,1,rep,packed,name=ids,proto3" json:"ids,omitempty"`
}

func (x *NotifyRemoveConnections) Reset() {
	*x = NotifyRemoveConnections{}
	if protoimpl.UnsafeEnabled {
		mi := &file_statistic_grpc_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NotifyRemoveConnections) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotifyRemoveConnections) ProtoMessage() {}

func (x *NotifyRemoveConnections) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotifyRemoveConnections.ProtoReflect.Descriptor instead.
func (*NotifyRemoveConnections) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{3}
}

func (x *NotifyRemoveConnections) GetIds() []uint64 {
	if x != nil {
		return x.Ids
	}
	return nil
}

var File_statistic_grpc_config_proto protoreflect.FileDescriptor

var file_statistic_grpc_config_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x20, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x40, 0x0a, 0x0a, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x66, 0x6c,
	0x6f, 0x77, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x16,
	0x0a, 0x06, 0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06,
	0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0xd1, 0x02, 0x0a, 0x0b, 0x6e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x12, 0x4d, 0x0a, 0x0a, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f,
	0x66, 0x6c, 0x6f, 0x77, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74,
	0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x74, 0x6f,
	0x74, 0x61, 0x6c, 0x5f, 0x66, 0x6c, 0x6f, 0x77, 0x48, 0x00, 0x52, 0x09, 0x74, 0x6f, 0x74, 0x61,
	0x6c, 0x46, 0x6c, 0x6f, 0x77, 0x12, 0x70, 0x0a, 0x16, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f,
	0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f,
	0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x48,
	0x00, 0x52, 0x14, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x4e, 0x65, 0x77, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x79, 0x0a, 0x19, 0x6e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3b, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74,
	0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x48, 0x00, 0x52, 0x17, 0x6e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x42, 0x06, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x59, 0x0a, 0x16, 0x6e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x12, 0x3f, 0x0a, 0x0b, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x79, 0x75, 0x68, 0x61,
	0x69, 0x69, 0x6e, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x2d, 0x0a, 0x19, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f,
	0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x64, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x04, 0x52,
	0x03, 0x69, 0x64, 0x73, 0x32, 0xed, 0x02, 0x0a, 0x0b, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x12, 0x59, 0x0a, 0x05, 0x63, 0x6f, 0x6e, 0x6e, 0x73, 0x12, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x38, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f,
	0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12,
	0x61, 0x0a, 0x0a, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x12, 0x3b, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x12, 0x4d, 0x0a, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x16, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x1a, 0x2c, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x66, 0x6c, 0x6f,
	0x77, 0x12, 0x51, 0x0a, 0x06, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x16, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x1a, 0x2d, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f, 0x64, 0x61,
	0x74, 0x61, 0x30, 0x01, 0x42, 0x3b, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f,
	0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_statistic_grpc_config_proto_rawDescOnce sync.Once
	file_statistic_grpc_config_proto_rawDescData = file_statistic_grpc_config_proto_rawDesc
)

func file_statistic_grpc_config_proto_rawDescGZIP() []byte {
	file_statistic_grpc_config_proto_rawDescOnce.Do(func() {
		file_statistic_grpc_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_statistic_grpc_config_proto_rawDescData)
	})
	return file_statistic_grpc_config_proto_rawDescData
}

var file_statistic_grpc_config_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_statistic_grpc_config_proto_goTypes = []any{
	(*TotalFlow)(nil),               // 0: yuhaiin.protos.statistic.service.total_flow
	(*NotifyData)(nil),              // 1: yuhaiin.protos.statistic.service.notify_data
	(*NotifyNewConnections)(nil),    // 2: yuhaiin.protos.statistic.service.notify_new_connections
	(*NotifyRemoveConnections)(nil), // 3: yuhaiin.protos.statistic.service.notify_remove_connections
	(*statistic.Connection)(nil),    // 4: yuhaiin.statistic.connection
	(*emptypb.Empty)(nil),           // 5: google.protobuf.Empty
}
var file_statistic_grpc_config_proto_depIdxs = []int32{
	0, // 0: yuhaiin.protos.statistic.service.notify_data.total_flow:type_name -> yuhaiin.protos.statistic.service.total_flow
	2, // 1: yuhaiin.protos.statistic.service.notify_data.notify_new_connections:type_name -> yuhaiin.protos.statistic.service.notify_new_connections
	3, // 2: yuhaiin.protos.statistic.service.notify_data.notify_remove_connections:type_name -> yuhaiin.protos.statistic.service.notify_remove_connections
	4, // 3: yuhaiin.protos.statistic.service.notify_new_connections.connections:type_name -> yuhaiin.statistic.connection
	5, // 4: yuhaiin.protos.statistic.service.connections.conns:input_type -> google.protobuf.Empty
	3, // 5: yuhaiin.protos.statistic.service.connections.close_conn:input_type -> yuhaiin.protos.statistic.service.notify_remove_connections
	5, // 6: yuhaiin.protos.statistic.service.connections.total:input_type -> google.protobuf.Empty
	5, // 7: yuhaiin.protos.statistic.service.connections.notify:input_type -> google.protobuf.Empty
	2, // 8: yuhaiin.protos.statistic.service.connections.conns:output_type -> yuhaiin.protos.statistic.service.notify_new_connections
	5, // 9: yuhaiin.protos.statistic.service.connections.close_conn:output_type -> google.protobuf.Empty
	0, // 10: yuhaiin.protos.statistic.service.connections.total:output_type -> yuhaiin.protos.statistic.service.total_flow
	1, // 11: yuhaiin.protos.statistic.service.connections.notify:output_type -> yuhaiin.protos.statistic.service.notify_data
	8, // [8:12] is the sub-list for method output_type
	4, // [4:8] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_statistic_grpc_config_proto_init() }
func file_statistic_grpc_config_proto_init() {
	if File_statistic_grpc_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_statistic_grpc_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*TotalFlow); i {
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
		file_statistic_grpc_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*NotifyData); i {
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
		file_statistic_grpc_config_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*NotifyNewConnections); i {
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
		file_statistic_grpc_config_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*NotifyRemoveConnections); i {
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
	file_statistic_grpc_config_proto_msgTypes[1].OneofWrappers = []any{
		(*NotifyData_TotalFlow)(nil),
		(*NotifyData_NotifyNewConnections)(nil),
		(*NotifyData_NotifyRemoveConnections)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_statistic_grpc_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_statistic_grpc_config_proto_goTypes,
		DependencyIndexes: file_statistic_grpc_config_proto_depIdxs,
		MessageInfos:      file_statistic_grpc_config_proto_msgTypes,
	}.Build()
	File_statistic_grpc_config_proto = out.File
	file_statistic_grpc_config_proto_rawDesc = nil
	file_statistic_grpc_config_proto_goTypes = nil
	file_statistic_grpc_config_proto_depIdxs = nil
}
