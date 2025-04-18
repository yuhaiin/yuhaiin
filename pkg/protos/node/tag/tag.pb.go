// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.4
// 	protoc        v6.30.1
// source: node/tag/tag.proto

package tag

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

type TagType int32

const (
	TagType_node   TagType = 0
	TagType_mirror TagType = 1
)

// Enum value maps for TagType.
var (
	TagType_name = map[int32]string{
		0: "node",
		1: "mirror",
	}
	TagType_value = map[string]int32{
		"node":   0,
		"mirror": 1,
	}
)

func (x TagType) Enum() *TagType {
	p := new(TagType)
	*p = x
	return p
}

func (x TagType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TagType) Descriptor() protoreflect.EnumDescriptor {
	return file_node_tag_tag_proto_enumTypes[0].Descriptor()
}

func (TagType) Type() protoreflect.EnumType {
	return &file_node_tag_tag_proto_enumTypes[0]
}

func (x TagType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

type Tags struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Tag         *string                `protobuf:"bytes,1,opt,name=tag"`
	xxx_hidden_Type        TagType                `protobuf:"varint,3,opt,name=type,enum=yuhaiin.tag.TagType"`
	xxx_hidden_Hash        []string               `protobuf:"bytes,2,rep,name=hash"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *Tags) Reset() {
	*x = Tags{}
	mi := &file_node_tag_tag_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Tags) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Tags) ProtoMessage() {}

func (x *Tags) ProtoReflect() protoreflect.Message {
	mi := &file_node_tag_tag_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Tags) GetTag() string {
	if x != nil {
		if x.xxx_hidden_Tag != nil {
			return *x.xxx_hidden_Tag
		}
		return ""
	}
	return ""
}

func (x *Tags) GetType() TagType {
	if x != nil {
		if protoimpl.X.Present(&(x.XXX_presence[0]), 1) {
			return x.xxx_hidden_Type
		}
	}
	return TagType_node
}

func (x *Tags) GetHash() []string {
	if x != nil {
		return x.xxx_hidden_Hash
	}
	return nil
}

func (x *Tags) SetTag(v string) {
	x.xxx_hidden_Tag = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 3)
}

func (x *Tags) SetType(v TagType) {
	x.xxx_hidden_Type = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 3)
}

func (x *Tags) SetHash(v []string) {
	x.xxx_hidden_Hash = v
}

func (x *Tags) HasTag() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Tags) HasType() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *Tags) ClearTag() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Tag = nil
}

func (x *Tags) ClearType() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Type = TagType_node
}

type Tags_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Tag  *string
	Type *TagType
	Hash []string
}

func (b0 Tags_builder) Build() *Tags {
	m0 := &Tags{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Tag != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 3)
		x.xxx_hidden_Tag = b.Tag
	}
	if b.Type != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 3)
		x.xxx_hidden_Type = *b.Type
	}
	x.xxx_hidden_Hash = b.Hash
	return m0
}

var File_node_tag_tag_proto protoreflect.FileDescriptor

var file_node_tag_tag_proto_rawDesc = string([]byte{
	0x0a, 0x12, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x74, 0x61, 0x67, 0x2f, 0x74, 0x61, 0x67, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x74, 0x61,
	0x67, 0x1a, 0x21, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x67, 0x6f, 0x5f, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x57, 0x0a, 0x04, 0x74, 0x61, 0x67, 0x73, 0x12, 0x10, 0x0a, 0x03,
	0x74, 0x61, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x74, 0x61, 0x67, 0x12, 0x29,
	0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x74, 0x61, 0x67, 0x2e, 0x74, 0x61, 0x67, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73,
	0x68, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x2a, 0x20, 0x0a,
	0x08, 0x74, 0x61, 0x67, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x12, 0x08, 0x0a, 0x04, 0x6e, 0x6f, 0x64,
	0x65, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x6d, 0x69, 0x72, 0x72, 0x6f, 0x72, 0x10, 0x01, 0x42,
	0x3a, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73,
	0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f,
	0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2f,
	0x74, 0x61, 0x67, 0x92, 0x03, 0x05, 0xd2, 0x3e, 0x02, 0x10, 0x03, 0x62, 0x08, 0x65, 0x64, 0x69,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x70, 0xe8, 0x07,
})

var file_node_tag_tag_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_node_tag_tag_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_node_tag_tag_proto_goTypes = []any{
	(TagType)(0), // 0: yuhaiin.tag.tag_type
	(*Tags)(nil), // 1: yuhaiin.tag.tags
}
var file_node_tag_tag_proto_depIdxs = []int32{
	0, // 0: yuhaiin.tag.tags.type:type_name -> yuhaiin.tag.tag_type
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_node_tag_tag_proto_init() }
func file_node_tag_tag_proto_init() {
	if File_node_tag_tag_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_node_tag_tag_proto_rawDesc), len(file_node_tag_tag_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_node_tag_tag_proto_goTypes,
		DependencyIndexes: file_node_tag_tag_proto_depIdxs,
		EnumInfos:         file_node_tag_tag_proto_enumTypes,
		MessageInfos:      file_node_tag_tag_proto_msgTypes,
	}.Build()
	File_node_tag_tag_proto = out.File
	file_node_tag_tag_proto_goTypes = nil
	file_node_tag_tag_proto_depIdxs = nil
}
