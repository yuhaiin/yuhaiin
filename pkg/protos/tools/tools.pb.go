// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.4
// 	protoc        v6.30.1
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

var File_tools_tools_proto protoreflect.FileDescriptor

var file_tools_tools_proto_rawDesc = string([]byte{
	0x0a, 0x11, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2f, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x74, 0x6f, 0x6f,
	0x6c, 0x73, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x21, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x67, 0x6f, 0x5f, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x46, 0x0a, 0x0a, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73,
	0x12, 0x38, 0x0a, 0x0a, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x74,
	0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x52, 0x0a,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73, 0x22, 0x3d, 0x0a, 0x09, 0x49, 0x6e,
	0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x61,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x22, 0x6e, 0x0a, 0x08, 0x4c, 0x69, 0x63,
	0x65, 0x6e, 0x73, 0x65, 0x73, 0x12, 0x30, 0x0a, 0x07, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x52, 0x07,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x12, 0x30, 0x0a, 0x07, 0x61, 0x6e, 0x64, 0x72, 0x6f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65,
	0x52, 0x07, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x22, 0x6b, 0x0a, 0x07, 0x4c, 0x69, 0x63,
	0x65, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x12, 0x18, 0x0a, 0x07, 0x6c, 0x69,
	0x63, 0x65, 0x6e, 0x73, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6c, 0x69, 0x63,
	0x65, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x5f,
	0x75, 0x72, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x6c, 0x69, 0x63, 0x65, 0x6e,
	0x73, 0x65, 0x5f, 0x75, 0x72, 0x6c, 0x32, 0x88, 0x01, 0x0a, 0x05, 0x74, 0x6f, 0x6f, 0x6c, 0x73,
	0x12, 0x42, 0x0a, 0x0d, 0x67, 0x65, 0x74, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63,
	0x65, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x19, 0x2e, 0x79, 0x75, 0x68, 0x61,
	0x69, 0x69, 0x6e, 0x2e, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66,
	0x61, 0x63, 0x65, 0x73, 0x12, 0x3b, 0x0a, 0x08, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x73,
	0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x17, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65,
	0x73, 0x42, 0x37, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69,
	0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x74, 0x6f, 0x6f,
	0x6c, 0x73, 0x92, 0x03, 0x05, 0xd2, 0x3e, 0x02, 0x10, 0x03, 0x62, 0x08, 0x65, 0x64, 0x69, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x70, 0xe8, 0x07,
})

var file_tools_tools_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_tools_tools_proto_goTypes = []any{
	(*Interfaces)(nil),    // 0: yuhaiin.tools.Interfaces
	(*Interface)(nil),     // 1: yuhaiin.tools.Interface
	(*Licenses)(nil),      // 2: yuhaiin.tools.Licenses
	(*License)(nil),       // 3: yuhaiin.tools.License
	(*emptypb.Empty)(nil), // 4: google.protobuf.Empty
}
var file_tools_tools_proto_depIdxs = []int32{
	1, // 0: yuhaiin.tools.Interfaces.interfaces:type_name -> yuhaiin.tools.Interface
	3, // 1: yuhaiin.tools.Licenses.yuhaiin:type_name -> yuhaiin.tools.License
	3, // 2: yuhaiin.tools.Licenses.android:type_name -> yuhaiin.tools.License
	4, // 3: yuhaiin.tools.tools.get_interface:input_type -> google.protobuf.Empty
	4, // 4: yuhaiin.tools.tools.licenses:input_type -> google.protobuf.Empty
	0, // 5: yuhaiin.tools.tools.get_interface:output_type -> yuhaiin.tools.Interfaces
	2, // 6: yuhaiin.tools.tools.licenses:output_type -> yuhaiin.tools.Licenses
	5, // [5:7] is the sub-list for method output_type
	3, // [3:5] is the sub-list for method input_type
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
			NumMessages:   4,
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
