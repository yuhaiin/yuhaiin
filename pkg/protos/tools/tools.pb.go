// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: tools/tools.proto

package tools

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/gofeaturespb"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Interfaces struct {
	state                 protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Interfaces *[]*Interface          `protobuf:"bytes,1,rep,name=interfaces"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *Interfaces) Reset() {
	*x = Interfaces{}
	mi := &file_tools_tools_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Interfaces) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Interfaces) ProtoMessage() {}

func (x *Interfaces) ProtoReflect() protoreflect.Message {
	mi := &file_tools_tools_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Interfaces) GetInterfaces() []*Interface {
	if x != nil {
		if x.xxx_hidden_Interfaces != nil {
			return *x.xxx_hidden_Interfaces
		}
	}
	return nil
}

func (x *Interfaces) SetInterfaces(v []*Interface) {
	x.xxx_hidden_Interfaces = &v
}

type Interfaces_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Interfaces []*Interface
}

func (b0 Interfaces_builder) Build() *Interfaces {
	m0 := &Interfaces{}
	b, x := &b0, m0
	_, _ = b, x
	x.xxx_hidden_Interfaces = &b.Interfaces
	return m0
}

type Interface struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Name        *string                `protobuf:"bytes,1,opt,name=name"`
	xxx_hidden_Addresses   []string               `protobuf:"bytes,2,rep,name=addresses"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *Interface) Reset() {
	*x = Interface{}
	mi := &file_tools_tools_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Interface) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Interface) ProtoMessage() {}

func (x *Interface) ProtoReflect() protoreflect.Message {
	mi := &file_tools_tools_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Interface) GetName() string {
	if x != nil {
		if x.xxx_hidden_Name != nil {
			return *x.xxx_hidden_Name
		}
		return ""
	}
	return ""
}

func (x *Interface) GetAddresses() []string {
	if x != nil {
		return x.xxx_hidden_Addresses
	}
	return nil
}

func (x *Interface) SetName(v string) {
	x.xxx_hidden_Name = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 2)
}

func (x *Interface) SetAddresses(v []string) {
	x.xxx_hidden_Addresses = v
}

func (x *Interface) HasName() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Interface) ClearName() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Name = nil
}

type Interface_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Name      *string
	Addresses []string
}

func (b0 Interface_builder) Build() *Interface {
	m0 := &Interface{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Name != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 2)
		x.xxx_hidden_Name = b.Name
	}
	x.xxx_hidden_Addresses = b.Addresses
	return m0
}

type Licenses struct {
	state              protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Yuhaiin *[]*License            `protobuf:"bytes,1,rep,name=yuhaiin"`
	xxx_hidden_Android *[]*License            `protobuf:"bytes,2,rep,name=android"`
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *Licenses) Reset() {
	*x = Licenses{}
	mi := &file_tools_tools_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Licenses) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Licenses) ProtoMessage() {}

func (x *Licenses) ProtoReflect() protoreflect.Message {
	mi := &file_tools_tools_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Licenses) GetYuhaiin() []*License {
	if x != nil {
		if x.xxx_hidden_Yuhaiin != nil {
			return *x.xxx_hidden_Yuhaiin
		}
	}
	return nil
}

func (x *Licenses) GetAndroid() []*License {
	if x != nil {
		if x.xxx_hidden_Android != nil {
			return *x.xxx_hidden_Android
		}
	}
	return nil
}

func (x *Licenses) SetYuhaiin(v []*License) {
	x.xxx_hidden_Yuhaiin = &v
}

func (x *Licenses) SetAndroid(v []*License) {
	x.xxx_hidden_Android = &v
}

type Licenses_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Yuhaiin []*License
	Android []*License
}

func (b0 Licenses_builder) Build() *Licenses {
	m0 := &Licenses{}
	b, x := &b0, m0
	_, _ = b, x
	x.xxx_hidden_Yuhaiin = &b.Yuhaiin
	x.xxx_hidden_Android = &b.Android
	return m0
}

type License struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Name        *string                `protobuf:"bytes,1,opt,name=name"`
	xxx_hidden_Url         *string                `protobuf:"bytes,2,opt,name=url"`
	xxx_hidden_License     *string                `protobuf:"bytes,3,opt,name=license"`
	xxx_hidden_LicenseUrl  *string                `protobuf:"bytes,4,opt,name=license_url"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *License) Reset() {
	*x = License{}
	mi := &file_tools_tools_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *License) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*License) ProtoMessage() {}

func (x *License) ProtoReflect() protoreflect.Message {
	mi := &file_tools_tools_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *License) GetName() string {
	if x != nil {
		if x.xxx_hidden_Name != nil {
			return *x.xxx_hidden_Name
		}
		return ""
	}
	return ""
}

func (x *License) GetUrl() string {
	if x != nil {
		if x.xxx_hidden_Url != nil {
			return *x.xxx_hidden_Url
		}
		return ""
	}
	return ""
}

func (x *License) GetLicense() string {
	if x != nil {
		if x.xxx_hidden_License != nil {
			return *x.xxx_hidden_License
		}
		return ""
	}
	return ""
}

func (x *License) GetLicenseUrl() string {
	if x != nil {
		if x.xxx_hidden_LicenseUrl != nil {
			return *x.xxx_hidden_LicenseUrl
		}
		return ""
	}
	return ""
}

func (x *License) SetName(v string) {
	x.xxx_hidden_Name = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 4)
}

func (x *License) SetUrl(v string) {
	x.xxx_hidden_Url = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 4)
}

func (x *License) SetLicense(v string) {
	x.xxx_hidden_License = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 4)
}

func (x *License) SetLicenseUrl(v string) {
	x.xxx_hidden_LicenseUrl = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 3, 4)
}

func (x *License) HasName() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *License) HasUrl() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *License) HasLicense() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 2)
}

func (x *License) HasLicenseUrl() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 3)
}

func (x *License) ClearName() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Name = nil
}

func (x *License) ClearUrl() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Url = nil
}

func (x *License) ClearLicense() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 2)
	x.xxx_hidden_License = nil
}

func (x *License) ClearLicenseUrl() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 3)
	x.xxx_hidden_LicenseUrl = nil
}

type License_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Name       *string
	Url        *string
	License    *string
	LicenseUrl *string
}

func (b0 License_builder) Build() *License {
	m0 := &License{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Name != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 4)
		x.xxx_hidden_Name = b.Name
	}
	if b.Url != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 4)
		x.xxx_hidden_Url = b.Url
	}
	if b.License != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 4)
		x.xxx_hidden_License = b.License
	}
	if b.LicenseUrl != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 3, 4)
		x.xxx_hidden_LicenseUrl = b.LicenseUrl
	}
	return m0
}

type Log struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Log         *string                `protobuf:"bytes,1,opt,name=log"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *Log) Reset() {
	*x = Log{}
	mi := &file_tools_tools_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Log) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Log) ProtoMessage() {}

func (x *Log) ProtoReflect() protoreflect.Message {
	mi := &file_tools_tools_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Log) GetLog() string {
	if x != nil {
		if x.xxx_hidden_Log != nil {
			return *x.xxx_hidden_Log
		}
		return ""
	}
	return ""
}

func (x *Log) SetLog(v string) {
	x.xxx_hidden_Log = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 1)
}

func (x *Log) HasLog() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Log) ClearLog() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Log = nil
}

type Log_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Log *string
}

func (b0 Log_builder) Build() *Log {
	m0 := &Log{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Log != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 1)
		x.xxx_hidden_Log = b.Log
	}
	return m0
}

type Logv2 struct {
	state          protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Log []string               `protobuf:"bytes,1,rep,name=log"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *Logv2) Reset() {
	*x = Logv2{}
	mi := &file_tools_tools_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Logv2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Logv2) ProtoMessage() {}

func (x *Logv2) ProtoReflect() protoreflect.Message {
	mi := &file_tools_tools_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Logv2) GetLog() []string {
	if x != nil {
		return x.xxx_hidden_Log
	}
	return nil
}

func (x *Logv2) SetLog(v []string) {
	x.xxx_hidden_Log = v
}

type Logv2_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Log []string
}

func (b0 Logv2_builder) Build() *Logv2 {
	m0 := &Logv2{}
	b, x := &b0, m0
	_, _ = b, x
	x.xxx_hidden_Log = b.Log
	return m0
}

var File_tools_tools_proto protoreflect.FileDescriptor

const file_tools_tools_proto_rawDesc = "" +
	"\n" +
	"\x11tools/tools.proto\x12\ryuhaiin.tools\x1a\x1bgoogle/protobuf/empty.proto\x1a!google/protobuf/go_features.proto\"F\n" +
	"\n" +
	"Interfaces\x128\n" +
	"\n" +
	"interfaces\x18\x01 \x03(\v2\x18.yuhaiin.tools.InterfaceR\n" +
	"interfaces\"=\n" +
	"\tInterface\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x1c\n" +
	"\taddresses\x18\x02 \x03(\tR\taddresses\"n\n" +
	"\bLicenses\x120\n" +
	"\ayuhaiin\x18\x01 \x03(\v2\x16.yuhaiin.tools.LicenseR\ayuhaiin\x120\n" +
	"\aandroid\x18\x02 \x03(\v2\x16.yuhaiin.tools.LicenseR\aandroid\"k\n" +
	"\aLicense\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x10\n" +
	"\x03url\x18\x02 \x01(\tR\x03url\x12\x18\n" +
	"\alicense\x18\x03 \x01(\tR\alicense\x12 \n" +
	"\vlicense_url\x18\x04 \x01(\tR\vlicense_url\"\x17\n" +
	"\x03Log\x12\x10\n" +
	"\x03log\x18\x01 \x01(\tR\x03log\"\x19\n" +
	"\x05Logv2\x12\x10\n" +
	"\x03log\x18\x01 \x03(\tR\x03log2\xf6\x01\n" +
	"\x05tools\x12B\n" +
	"\rget_interface\x12\x16.google.protobuf.Empty\x1a\x19.yuhaiin.tools.Interfaces\x12;\n" +
	"\blicenses\x12\x16.google.protobuf.Empty\x1a\x17.yuhaiin.tools.Licenses\x123\n" +
	"\x03log\x12\x16.google.protobuf.Empty\x1a\x12.yuhaiin.tools.Log0\x01\x127\n" +
	"\x05logv2\x12\x16.google.protobuf.Empty\x1a\x14.yuhaiin.tools.Logv20\x01B7Z-github.com/Asutorufa/yuhaiin/pkg/protos/tools\x92\x03\x05\xd2>\x02\x10\x03b\beditionsp\xe8\a"

var file_tools_tools_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_tools_tools_proto_goTypes = []any{
	(*Interfaces)(nil),    // 0: yuhaiin.tools.Interfaces
	(*Interface)(nil),     // 1: yuhaiin.tools.Interface
	(*Licenses)(nil),      // 2: yuhaiin.tools.Licenses
	(*License)(nil),       // 3: yuhaiin.tools.License
	(*Log)(nil),           // 4: yuhaiin.tools.Log
	(*Logv2)(nil),         // 5: yuhaiin.tools.Logv2
	(*emptypb.Empty)(nil), // 6: google.protobuf.Empty
}
var file_tools_tools_proto_depIdxs = []int32{
	1, // 0: yuhaiin.tools.Interfaces.interfaces:type_name -> yuhaiin.tools.Interface
	3, // 1: yuhaiin.tools.Licenses.yuhaiin:type_name -> yuhaiin.tools.License
	3, // 2: yuhaiin.tools.Licenses.android:type_name -> yuhaiin.tools.License
	6, // 3: yuhaiin.tools.tools.get_interface:input_type -> google.protobuf.Empty
	6, // 4: yuhaiin.tools.tools.licenses:input_type -> google.protobuf.Empty
	6, // 5: yuhaiin.tools.tools.log:input_type -> google.protobuf.Empty
	6, // 6: yuhaiin.tools.tools.logv2:input_type -> google.protobuf.Empty
	0, // 7: yuhaiin.tools.tools.get_interface:output_type -> yuhaiin.tools.Interfaces
	2, // 8: yuhaiin.tools.tools.licenses:output_type -> yuhaiin.tools.Licenses
	4, // 9: yuhaiin.tools.tools.log:output_type -> yuhaiin.tools.Log
	5, // 10: yuhaiin.tools.tools.logv2:output_type -> yuhaiin.tools.Logv2
	7, // [7:11] is the sub-list for method output_type
	3, // [3:7] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_tools_tools_proto_init() }
func file_tools_tools_proto_init() {
	if File_tools_tools_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_tools_tools_proto_rawDesc), len(file_tools_tools_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_tools_tools_proto_goTypes,
		DependencyIndexes: file_tools_tools_proto_depIdxs,
		MessageInfos:      file_tools_tools_proto_msgTypes,
	}.Build()
	File_tools_tools_proto = out.File
	file_tools_tools_proto_goTypes = nil
	file_tools_tools_proto_depIdxs = nil
}
