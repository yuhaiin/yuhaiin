// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.7
// source: config/bypass/bypass.proto

package bypass

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Mode int32

const (
	Mode_bypass Mode = 0
	Mode_direct Mode = 1
	Mode_proxy  Mode = 2
	Mode_block  Mode = 3
)

// Enum value maps for Mode.
var (
	Mode_name = map[int32]string{
		0: "bypass",
		1: "direct",
		2: "proxy",
		3: "block",
	}
	Mode_value = map[string]int32{
		"bypass": 0,
		"direct": 1,
		"proxy":  2,
		"block":  3,
	}
)

func (x Mode) Enum() *Mode {
	p := new(Mode)
	*p = x
	return p
}

func (x Mode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Mode) Descriptor() protoreflect.EnumDescriptor {
	return file_config_bypass_bypass_proto_enumTypes[0].Descriptor()
}

func (Mode) Type() protoreflect.EnumType {
	return &file_config_bypass_bypass_proto_enumTypes[0]
}

func (x Mode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Mode.Descriptor instead.
func (Mode) EnumDescriptor() ([]byte, []int) {
	return file_config_bypass_bypass_proto_rawDescGZIP(), []int{0}
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tcp        Mode            `protobuf:"varint,3,opt,name=tcp,proto3,enum=yuhaiin.bypass.Mode" json:"tcp,omitempty"`
	Udp        Mode            `protobuf:"varint,4,opt,name=udp,proto3,enum=yuhaiin.bypass.Mode" json:"udp,omitempty"`
	BypassFile string          `protobuf:"bytes,2,opt,name=bypass_file,proto3" json:"bypass_file,omitempty"`
	CustomRule map[string]Mode `protobuf:"bytes,5,rep,name=custom_rule,proto3" json:"custom_rule,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3,enum=yuhaiin.bypass.Mode"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_bypass_bypass_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_config_bypass_bypass_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_config_bypass_bypass_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetTcp() Mode {
	if x != nil {
		return x.Tcp
	}
	return Mode_bypass
}

func (x *Config) GetUdp() Mode {
	if x != nil {
		return x.Udp
	}
	return Mode_bypass
}

func (x *Config) GetBypassFile() string {
	if x != nil {
		return x.BypassFile
	}
	return ""
}

func (x *Config) GetCustomRule() map[string]Mode {
	if x != nil {
		return x.CustomRule
	}
	return nil
}

var File_config_bypass_bypass_proto protoreflect.FileDescriptor

var file_config_bypass_bypass_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2f,
	0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x22, 0x99, 0x02, 0x0a,
	0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x26, 0x0a, 0x03, 0x74, 0x63, 0x70, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62,
	0x79, 0x70, 0x61, 0x73, 0x73, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x52, 0x03, 0x74, 0x63, 0x70, 0x12,
	0x26, 0x0a, 0x03, 0x75, 0x64, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2e, 0x6d, 0x6f,
	0x64, 0x65, 0x52, 0x03, 0x75, 0x64, 0x70, 0x12, 0x20, 0x0a, 0x0b, 0x62, 0x79, 0x70, 0x61, 0x73,
	0x73, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x62, 0x79,
	0x70, 0x61, 0x73, 0x73, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x12, 0x48, 0x0a, 0x0b, 0x63, 0x75, 0x73,
	0x74, 0x6f, 0x6d, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26,
	0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x52, 0x75, 0x6c,
	0x65, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x72,
	0x75, 0x6c, 0x65, 0x1a, 0x53, 0x0a, 0x0f, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x52, 0x75, 0x6c,
	0x65, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69,
	0x6e, 0x2e, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x2a, 0x34, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65,
	0x12, 0x0a, 0x0a, 0x06, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06,
	0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x10, 0x02, 0x12, 0x09, 0x0a, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x10, 0x03, 0x42, 0x37,
	0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75,
	0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f, 0x70,
	0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2f, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_config_bypass_bypass_proto_rawDescOnce sync.Once
	file_config_bypass_bypass_proto_rawDescData = file_config_bypass_bypass_proto_rawDesc
)

func file_config_bypass_bypass_proto_rawDescGZIP() []byte {
	file_config_bypass_bypass_proto_rawDescOnce.Do(func() {
		file_config_bypass_bypass_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_bypass_bypass_proto_rawDescData)
	})
	return file_config_bypass_bypass_proto_rawDescData
}

var file_config_bypass_bypass_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_config_bypass_bypass_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_config_bypass_bypass_proto_goTypes = []interface{}{
	(Mode)(0),      // 0: yuhaiin.bypass.mode
	(*Config)(nil), // 1: yuhaiin.bypass.config
	nil,            // 2: yuhaiin.bypass.config.CustomRuleEntry
}
var file_config_bypass_bypass_proto_depIdxs = []int32{
	0, // 0: yuhaiin.bypass.config.tcp:type_name -> yuhaiin.bypass.mode
	0, // 1: yuhaiin.bypass.config.udp:type_name -> yuhaiin.bypass.mode
	2, // 2: yuhaiin.bypass.config.custom_rule:type_name -> yuhaiin.bypass.config.CustomRuleEntry
	0, // 3: yuhaiin.bypass.config.CustomRuleEntry.value:type_name -> yuhaiin.bypass.mode
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_config_bypass_bypass_proto_init() }
func file_config_bypass_bypass_proto_init() {
	if File_config_bypass_bypass_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_bypass_bypass_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
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
			RawDescriptor: file_config_bypass_bypass_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_bypass_bypass_proto_goTypes,
		DependencyIndexes: file_config_bypass_bypass_proto_depIdxs,
		EnumInfos:         file_config_bypass_bypass_proto_enumTypes,
		MessageInfos:      file_config_bypass_bypass_proto_msgTypes,
	}.Build()
	File_config_bypass_bypass_proto = out.File
	file_config_bypass_bypass_proto_rawDesc = nil
	file_config_bypass_bypass_proto_goTypes = nil
	file_config_bypass_bypass_proto_depIdxs = nil
}