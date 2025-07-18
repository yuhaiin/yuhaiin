// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: config/config.proto

package config

import (
	backup "github.com/Asutorufa/yuhaiin/pkg/protos/backup"
	bypass "github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	dns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	listener "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	log "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
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

type Setting struct {
	state                                 protoimpl.MessageState  `protogen:"opaque.v1"`
	xxx_hidden_Ipv6                       bool                    `protobuf:"varint,7,opt,name=ipv6"`
	xxx_hidden_Ipv6LocalAddrPreferUnicast bool                    `protobuf:"varint,10,opt,name=ipv6_local_addr_prefer_unicast"`
	xxx_hidden_UseDefaultInterface        bool                    `protobuf:"varint,13,opt,name=use_default_interface"`
	xxx_hidden_NetInterface               *string                 `protobuf:"bytes,6,opt,name=net_interface"`
	xxx_hidden_SystemProxy                *SystemProxy            `protobuf:"bytes,1,opt,name=system_proxy"`
	xxx_hidden_Bypass                     *bypass.Config          `protobuf:"bytes,2,opt,name=bypass"`
	xxx_hidden_Dns                        *dns.DnsConfig          `protobuf:"bytes,4,opt,name=dns"`
	xxx_hidden_Server                     *listener.InboundConfig `protobuf:"bytes,5,opt,name=server"`
	xxx_hidden_Logcat                     *log.Logcat             `protobuf:"bytes,8,opt,name=logcat"`
	xxx_hidden_ConfigVersion              *ConfigVersion          `protobuf:"bytes,9,opt,name=config_version"`
	xxx_hidden_Platform                   *Platform               `protobuf:"bytes,11,opt,name=platform"`
	xxx_hidden_AdvancedConfig             *AdvancedConfig         `protobuf:"bytes,12,opt,name=advanced_config"`
	xxx_hidden_Backup                     *backup.BackupOption    `protobuf:"bytes,14,opt,name=backup"`
	XXX_raceDetectHookData                protoimpl.RaceDetectHookData
	XXX_presence                          [1]uint32
	unknownFields                         protoimpl.UnknownFields
	sizeCache                             protoimpl.SizeCache
}

func (x *Setting) Reset() {
	*x = Setting{}
	mi := &file_config_config_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Setting) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Setting) ProtoMessage() {}

func (x *Setting) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Setting) GetIpv6() bool {
	if x != nil {
		return x.xxx_hidden_Ipv6
	}
	return false
}

func (x *Setting) GetIpv6LocalAddrPreferUnicast() bool {
	if x != nil {
		return x.xxx_hidden_Ipv6LocalAddrPreferUnicast
	}
	return false
}

func (x *Setting) GetUseDefaultInterface() bool {
	if x != nil {
		return x.xxx_hidden_UseDefaultInterface
	}
	return false
}

func (x *Setting) GetNetInterface() string {
	if x != nil {
		if x.xxx_hidden_NetInterface != nil {
			return *x.xxx_hidden_NetInterface
		}
		return ""
	}
	return ""
}

func (x *Setting) GetSystemProxy() *SystemProxy {
	if x != nil {
		return x.xxx_hidden_SystemProxy
	}
	return nil
}

func (x *Setting) GetBypass() *bypass.Config {
	if x != nil {
		return x.xxx_hidden_Bypass
	}
	return nil
}

func (x *Setting) GetDns() *dns.DnsConfig {
	if x != nil {
		return x.xxx_hidden_Dns
	}
	return nil
}

func (x *Setting) GetServer() *listener.InboundConfig {
	if x != nil {
		return x.xxx_hidden_Server
	}
	return nil
}

func (x *Setting) GetLogcat() *log.Logcat {
	if x != nil {
		return x.xxx_hidden_Logcat
	}
	return nil
}

func (x *Setting) GetConfigVersion() *ConfigVersion {
	if x != nil {
		return x.xxx_hidden_ConfigVersion
	}
	return nil
}

func (x *Setting) GetPlatform() *Platform {
	if x != nil {
		return x.xxx_hidden_Platform
	}
	return nil
}

func (x *Setting) GetAdvancedConfig() *AdvancedConfig {
	if x != nil {
		return x.xxx_hidden_AdvancedConfig
	}
	return nil
}

func (x *Setting) GetBackup() *backup.BackupOption {
	if x != nil {
		return x.xxx_hidden_Backup
	}
	return nil
}

func (x *Setting) SetIpv6(v bool) {
	x.xxx_hidden_Ipv6 = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 13)
}

func (x *Setting) SetIpv6LocalAddrPreferUnicast(v bool) {
	x.xxx_hidden_Ipv6LocalAddrPreferUnicast = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 13)
}

func (x *Setting) SetUseDefaultInterface(v bool) {
	x.xxx_hidden_UseDefaultInterface = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 13)
}

func (x *Setting) SetNetInterface(v string) {
	x.xxx_hidden_NetInterface = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 3, 13)
}

func (x *Setting) SetSystemProxy(v *SystemProxy) {
	x.xxx_hidden_SystemProxy = v
}

func (x *Setting) SetBypass(v *bypass.Config) {
	x.xxx_hidden_Bypass = v
}

func (x *Setting) SetDns(v *dns.DnsConfig) {
	x.xxx_hidden_Dns = v
}

func (x *Setting) SetServer(v *listener.InboundConfig) {
	x.xxx_hidden_Server = v
}

func (x *Setting) SetLogcat(v *log.Logcat) {
	x.xxx_hidden_Logcat = v
}

func (x *Setting) SetConfigVersion(v *ConfigVersion) {
	x.xxx_hidden_ConfigVersion = v
}

func (x *Setting) SetPlatform(v *Platform) {
	x.xxx_hidden_Platform = v
}

func (x *Setting) SetAdvancedConfig(v *AdvancedConfig) {
	x.xxx_hidden_AdvancedConfig = v
}

func (x *Setting) SetBackup(v *backup.BackupOption) {
	x.xxx_hidden_Backup = v
}

func (x *Setting) HasIpv6() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Setting) HasIpv6LocalAddrPreferUnicast() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *Setting) HasUseDefaultInterface() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 2)
}

func (x *Setting) HasNetInterface() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 3)
}

func (x *Setting) HasSystemProxy() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_SystemProxy != nil
}

func (x *Setting) HasBypass() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Bypass != nil
}

func (x *Setting) HasDns() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Dns != nil
}

func (x *Setting) HasServer() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Server != nil
}

func (x *Setting) HasLogcat() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Logcat != nil
}

func (x *Setting) HasConfigVersion() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_ConfigVersion != nil
}

func (x *Setting) HasPlatform() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Platform != nil
}

func (x *Setting) HasAdvancedConfig() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_AdvancedConfig != nil
}

func (x *Setting) HasBackup() bool {
	if x == nil {
		return false
	}
	return x.xxx_hidden_Backup != nil
}

func (x *Setting) ClearIpv6() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Ipv6 = false
}

func (x *Setting) ClearIpv6LocalAddrPreferUnicast() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Ipv6LocalAddrPreferUnicast = false
}

func (x *Setting) ClearUseDefaultInterface() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 2)
	x.xxx_hidden_UseDefaultInterface = false
}

func (x *Setting) ClearNetInterface() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 3)
	x.xxx_hidden_NetInterface = nil
}

func (x *Setting) ClearSystemProxy() {
	x.xxx_hidden_SystemProxy = nil
}

func (x *Setting) ClearBypass() {
	x.xxx_hidden_Bypass = nil
}

func (x *Setting) ClearDns() {
	x.xxx_hidden_Dns = nil
}

func (x *Setting) ClearServer() {
	x.xxx_hidden_Server = nil
}

func (x *Setting) ClearLogcat() {
	x.xxx_hidden_Logcat = nil
}

func (x *Setting) ClearConfigVersion() {
	x.xxx_hidden_ConfigVersion = nil
}

func (x *Setting) ClearPlatform() {
	x.xxx_hidden_Platform = nil
}

func (x *Setting) ClearAdvancedConfig() {
	x.xxx_hidden_AdvancedConfig = nil
}

func (x *Setting) ClearBackup() {
	x.xxx_hidden_Backup = nil
}

type Setting_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Ipv6                       *bool
	Ipv6LocalAddrPreferUnicast *bool
	UseDefaultInterface        *bool
	// net_interface, eg: eth0
	NetInterface   *string
	SystemProxy    *SystemProxy
	Bypass         *bypass.Config
	Dns            *dns.DnsConfig
	Server         *listener.InboundConfig
	Logcat         *log.Logcat
	ConfigVersion  *ConfigVersion
	Platform       *Platform
	AdvancedConfig *AdvancedConfig
	Backup         *backup.BackupOption
}

func (b0 Setting_builder) Build() *Setting {
	m0 := &Setting{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Ipv6 != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 13)
		x.xxx_hidden_Ipv6 = *b.Ipv6
	}
	if b.Ipv6LocalAddrPreferUnicast != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 13)
		x.xxx_hidden_Ipv6LocalAddrPreferUnicast = *b.Ipv6LocalAddrPreferUnicast
	}
	if b.UseDefaultInterface != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 13)
		x.xxx_hidden_UseDefaultInterface = *b.UseDefaultInterface
	}
	if b.NetInterface != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 3, 13)
		x.xxx_hidden_NetInterface = b.NetInterface
	}
	x.xxx_hidden_SystemProxy = b.SystemProxy
	x.xxx_hidden_Bypass = b.Bypass
	x.xxx_hidden_Dns = b.Dns
	x.xxx_hidden_Server = b.Server
	x.xxx_hidden_Logcat = b.Logcat
	x.xxx_hidden_ConfigVersion = b.ConfigVersion
	x.xxx_hidden_Platform = b.Platform
	x.xxx_hidden_AdvancedConfig = b.AdvancedConfig
	x.xxx_hidden_Backup = b.Backup
	return m0
}

type AdvancedConfig struct {
	state                        protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_UdpBufferSize     int32                  `protobuf:"varint,1,opt,name=udp_buffer_size"`
	xxx_hidden_RelayBufferSize   int32                  `protobuf:"varint,2,opt,name=relay_buffer_size"`
	xxx_hidden_UdpRingbufferSize int32                  `protobuf:"varint,3,opt,name=udp_ringbuffer_size"`
	XXX_raceDetectHookData       protoimpl.RaceDetectHookData
	XXX_presence                 [1]uint32
	unknownFields                protoimpl.UnknownFields
	sizeCache                    protoimpl.SizeCache
}

func (x *AdvancedConfig) Reset() {
	*x = AdvancedConfig{}
	mi := &file_config_config_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdvancedConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdvancedConfig) ProtoMessage() {}

func (x *AdvancedConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *AdvancedConfig) GetUdpBufferSize() int32 {
	if x != nil {
		return x.xxx_hidden_UdpBufferSize
	}
	return 0
}

func (x *AdvancedConfig) GetRelayBufferSize() int32 {
	if x != nil {
		return x.xxx_hidden_RelayBufferSize
	}
	return 0
}

func (x *AdvancedConfig) GetUdpRingbufferSize() int32 {
	if x != nil {
		return x.xxx_hidden_UdpRingbufferSize
	}
	return 0
}

func (x *AdvancedConfig) SetUdpBufferSize(v int32) {
	x.xxx_hidden_UdpBufferSize = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 3)
}

func (x *AdvancedConfig) SetRelayBufferSize(v int32) {
	x.xxx_hidden_RelayBufferSize = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 3)
}

func (x *AdvancedConfig) SetUdpRingbufferSize(v int32) {
	x.xxx_hidden_UdpRingbufferSize = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 3)
}

func (x *AdvancedConfig) HasUdpBufferSize() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *AdvancedConfig) HasRelayBufferSize() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *AdvancedConfig) HasUdpRingbufferSize() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 2)
}

func (x *AdvancedConfig) ClearUdpBufferSize() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_UdpBufferSize = 0
}

func (x *AdvancedConfig) ClearRelayBufferSize() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_RelayBufferSize = 0
}

func (x *AdvancedConfig) ClearUdpRingbufferSize() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 2)
	x.xxx_hidden_UdpRingbufferSize = 0
}

type AdvancedConfig_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	UdpBufferSize     *int32
	RelayBufferSize   *int32
	UdpRingbufferSize *int32
}

func (b0 AdvancedConfig_builder) Build() *AdvancedConfig {
	m0 := &AdvancedConfig{}
	b, x := &b0, m0
	_, _ = b, x
	if b.UdpBufferSize != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 3)
		x.xxx_hidden_UdpBufferSize = *b.UdpBufferSize
	}
	if b.RelayBufferSize != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 3)
		x.xxx_hidden_RelayBufferSize = *b.RelayBufferSize
	}
	if b.UdpRingbufferSize != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 3)
		x.xxx_hidden_UdpRingbufferSize = *b.UdpRingbufferSize
	}
	return m0
}

type SystemProxy struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Http        bool                   `protobuf:"varint,2,opt,name=http"`
	xxx_hidden_Socks5      bool                   `protobuf:"varint,3,opt,name=socks5"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *SystemProxy) Reset() {
	*x = SystemProxy{}
	mi := &file_config_config_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SystemProxy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SystemProxy) ProtoMessage() {}

func (x *SystemProxy) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *SystemProxy) GetHttp() bool {
	if x != nil {
		return x.xxx_hidden_Http
	}
	return false
}

func (x *SystemProxy) GetSocks5() bool {
	if x != nil {
		return x.xxx_hidden_Socks5
	}
	return false
}

func (x *SystemProxy) SetHttp(v bool) {
	x.xxx_hidden_Http = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 2)
}

func (x *SystemProxy) SetSocks5(v bool) {
	x.xxx_hidden_Socks5 = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 2)
}

func (x *SystemProxy) HasHttp() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *SystemProxy) HasSocks5() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *SystemProxy) ClearHttp() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Http = false
}

func (x *SystemProxy) ClearSocks5() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Socks5 = false
}

type SystemProxy_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Http   *bool
	Socks5 *bool
}

func (b0 SystemProxy_builder) Build() *SystemProxy {
	m0 := &SystemProxy{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Http != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 2)
		x.xxx_hidden_Http = *b.Http
	}
	if b.Socks5 != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 2)
		x.xxx_hidden_Socks5 = *b.Socks5
	}
	return m0
}

type Info struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Version     *string                `protobuf:"bytes,1,opt,name=version"`
	xxx_hidden_Commit      *string                `protobuf:"bytes,2,opt,name=commit"`
	xxx_hidden_BuildTime   *string                `protobuf:"bytes,3,opt,name=build_time"`
	xxx_hidden_GoVersion   *string                `protobuf:"bytes,4,opt,name=go_version"`
	xxx_hidden_Arch        *string                `protobuf:"bytes,5,opt,name=arch"`
	xxx_hidden_Platform    *string                `protobuf:"bytes,6,opt,name=platform"`
	xxx_hidden_Os          *string                `protobuf:"bytes,7,opt,name=os"`
	xxx_hidden_Compiler    *string                `protobuf:"bytes,8,opt,name=compiler"`
	xxx_hidden_Build       []string               `protobuf:"bytes,9,rep,name=build"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *Info) Reset() {
	*x = Info{}
	mi := &file_config_config_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Info) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Info) ProtoMessage() {}

func (x *Info) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Info) GetVersion() string {
	if x != nil {
		if x.xxx_hidden_Version != nil {
			return *x.xxx_hidden_Version
		}
		return ""
	}
	return ""
}

func (x *Info) GetCommit() string {
	if x != nil {
		if x.xxx_hidden_Commit != nil {
			return *x.xxx_hidden_Commit
		}
		return ""
	}
	return ""
}

func (x *Info) GetBuildTime() string {
	if x != nil {
		if x.xxx_hidden_BuildTime != nil {
			return *x.xxx_hidden_BuildTime
		}
		return ""
	}
	return ""
}

func (x *Info) GetGoVersion() string {
	if x != nil {
		if x.xxx_hidden_GoVersion != nil {
			return *x.xxx_hidden_GoVersion
		}
		return ""
	}
	return ""
}

func (x *Info) GetArch() string {
	if x != nil {
		if x.xxx_hidden_Arch != nil {
			return *x.xxx_hidden_Arch
		}
		return ""
	}
	return ""
}

func (x *Info) GetPlatform() string {
	if x != nil {
		if x.xxx_hidden_Platform != nil {
			return *x.xxx_hidden_Platform
		}
		return ""
	}
	return ""
}

func (x *Info) GetOs() string {
	if x != nil {
		if x.xxx_hidden_Os != nil {
			return *x.xxx_hidden_Os
		}
		return ""
	}
	return ""
}

func (x *Info) GetCompiler() string {
	if x != nil {
		if x.xxx_hidden_Compiler != nil {
			return *x.xxx_hidden_Compiler
		}
		return ""
	}
	return ""
}

func (x *Info) GetBuild_() []string {
	if x != nil {
		return x.xxx_hidden_Build
	}
	return nil
}

func (x *Info) SetVersion(v string) {
	x.xxx_hidden_Version = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 9)
}

func (x *Info) SetCommit(v string) {
	x.xxx_hidden_Commit = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 1, 9)
}

func (x *Info) SetBuildTime(v string) {
	x.xxx_hidden_BuildTime = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 2, 9)
}

func (x *Info) SetGoVersion(v string) {
	x.xxx_hidden_GoVersion = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 3, 9)
}

func (x *Info) SetArch(v string) {
	x.xxx_hidden_Arch = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 4, 9)
}

func (x *Info) SetPlatform(v string) {
	x.xxx_hidden_Platform = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 5, 9)
}

func (x *Info) SetOs(v string) {
	x.xxx_hidden_Os = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 6, 9)
}

func (x *Info) SetCompiler(v string) {
	x.xxx_hidden_Compiler = &v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 7, 9)
}

func (x *Info) SetBuild_(v []string) {
	x.xxx_hidden_Build = v
}

func (x *Info) HasVersion() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Info) HasCommit() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 1)
}

func (x *Info) HasBuildTime() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 2)
}

func (x *Info) HasGoVersion() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 3)
}

func (x *Info) HasArch() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 4)
}

func (x *Info) HasPlatform() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 5)
}

func (x *Info) HasOs() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 6)
}

func (x *Info) HasCompiler() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 7)
}

func (x *Info) ClearVersion() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Version = nil
}

func (x *Info) ClearCommit() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 1)
	x.xxx_hidden_Commit = nil
}

func (x *Info) ClearBuildTime() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 2)
	x.xxx_hidden_BuildTime = nil
}

func (x *Info) ClearGoVersion() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 3)
	x.xxx_hidden_GoVersion = nil
}

func (x *Info) ClearArch() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 4)
	x.xxx_hidden_Arch = nil
}

func (x *Info) ClearPlatform() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 5)
	x.xxx_hidden_Platform = nil
}

func (x *Info) ClearOs() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 6)
	x.xxx_hidden_Os = nil
}

func (x *Info) ClearCompiler() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 7)
	x.xxx_hidden_Compiler = nil
}

type Info_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Version   *string
	Commit    *string
	BuildTime *string
	GoVersion *string
	Arch      *string
	Platform  *string
	Os        *string
	Compiler  *string
	Build_    []string
}

func (b0 Info_builder) Build() *Info {
	m0 := &Info{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Version != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 9)
		x.xxx_hidden_Version = b.Version
	}
	if b.Commit != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 1, 9)
		x.xxx_hidden_Commit = b.Commit
	}
	if b.BuildTime != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 2, 9)
		x.xxx_hidden_BuildTime = b.BuildTime
	}
	if b.GoVersion != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 3, 9)
		x.xxx_hidden_GoVersion = b.GoVersion
	}
	if b.Arch != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 4, 9)
		x.xxx_hidden_Arch = b.Arch
	}
	if b.Platform != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 5, 9)
		x.xxx_hidden_Platform = b.Platform
	}
	if b.Os != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 6, 9)
		x.xxx_hidden_Os = b.Os
	}
	if b.Compiler != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 7, 9)
		x.xxx_hidden_Compiler = b.Compiler
	}
	x.xxx_hidden_Build = b.Build_
	return m0
}

type ConfigVersion struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_Version     uint64                 `protobuf:"varint,1,opt,name=version"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *ConfigVersion) Reset() {
	*x = ConfigVersion{}
	mi := &file_config_config_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConfigVersion) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigVersion) ProtoMessage() {}

func (x *ConfigVersion) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *ConfigVersion) GetVersion() uint64 {
	if x != nil {
		return x.xxx_hidden_Version
	}
	return 0
}

func (x *ConfigVersion) SetVersion(v uint64) {
	x.xxx_hidden_Version = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 1)
}

func (x *ConfigVersion) HasVersion() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *ConfigVersion) ClearVersion() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_Version = 0
}

type ConfigVersion_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	Version *uint64
}

func (b0 ConfigVersion_builder) Build() *ConfigVersion {
	m0 := &ConfigVersion{}
	b, x := &b0, m0
	_, _ = b, x
	if b.Version != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 1)
		x.xxx_hidden_Version = *b.Version
	}
	return m0
}

type Platform struct {
	state                  protoimpl.MessageState `protogen:"opaque.v1"`
	xxx_hidden_AndroidApp  bool                   `protobuf:"varint,1,opt,name=android_app"`
	XXX_raceDetectHookData protoimpl.RaceDetectHookData
	XXX_presence           [1]uint32
	unknownFields          protoimpl.UnknownFields
	sizeCache              protoimpl.SizeCache
}

func (x *Platform) Reset() {
	*x = Platform{}
	mi := &file_config_config_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Platform) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Platform) ProtoMessage() {}

func (x *Platform) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Platform) GetAndroidApp() bool {
	if x != nil {
		return x.xxx_hidden_AndroidApp
	}
	return false
}

func (x *Platform) SetAndroidApp(v bool) {
	x.xxx_hidden_AndroidApp = v
	protoimpl.X.SetPresent(&(x.XXX_presence[0]), 0, 1)
}

func (x *Platform) HasAndroidApp() bool {
	if x == nil {
		return false
	}
	return protoimpl.X.Present(&(x.XXX_presence[0]), 0)
}

func (x *Platform) ClearAndroidApp() {
	protoimpl.X.ClearPresent(&(x.XXX_presence[0]), 0)
	x.xxx_hidden_AndroidApp = false
}

type Platform_builder struct {
	_ [0]func() // Prevents comparability and use of unkeyed literals for the builder.

	AndroidApp *bool
}

func (b0 Platform_builder) Build() *Platform {
	m0 := &Platform{}
	b, x := &b0, m0
	_, _ = b, x
	if b.AndroidApp != nil {
		protoimpl.X.SetPresentNonAtomic(&(x.XXX_presence[0]), 0, 1)
		x.xxx_hidden_AndroidApp = *b.AndroidApp
	}
	return m0
}

var File_config_config_proto protoreflect.FileDescriptor

const file_config_config_proto_rawDesc = "" +
	"\n" +
	"\x13config/config.proto\x12\x0eyuhaiin.config\x1a\x14config/log/log.proto\x1a\x1aconfig/bypass/bypass.proto\x1a\x14config/dns/dns.proto\x1a\x1econfig/listener/listener.proto\x1a\x13backup/backup.proto\x1a!google/protobuf/go_features.proto\"\xc5\x05\n" +
	"\asetting\x12\x12\n" +
	"\x04ipv6\x18\a \x01(\bR\x04ipv6\x12F\n" +
	"\x1eipv6_local_addr_prefer_unicast\x18\n" +
	" \x01(\bR\x1eipv6_local_addr_prefer_unicast\x124\n" +
	"\x15use_default_interface\x18\r \x01(\bR\x15use_default_interface\x12$\n" +
	"\rnet_interface\x18\x06 \x01(\tR\rnet_interface\x12@\n" +
	"\fsystem_proxy\x18\x01 \x01(\v2\x1c.yuhaiin.config.system_proxyR\fsystem_proxy\x12.\n" +
	"\x06bypass\x18\x02 \x01(\v2\x16.yuhaiin.bypass.configR\x06bypass\x12)\n" +
	"\x03dns\x18\x04 \x01(\v2\x17.yuhaiin.dns.dns_configR\x03dns\x128\n" +
	"\x06server\x18\x05 \x01(\v2 .yuhaiin.listener.inbound_configR\x06server\x12+\n" +
	"\x06logcat\x18\b \x01(\v2\x13.yuhaiin.log.logcatR\x06logcat\x12F\n" +
	"\x0econfig_version\x18\t \x01(\v2\x1e.yuhaiin.config.config_versionR\x0econfig_version\x124\n" +
	"\bplatform\x18\v \x01(\v2\x18.yuhaiin.config.platformR\bplatform\x12I\n" +
	"\x0fadvanced_config\x18\f \x01(\v2\x1f.yuhaiin.config.advanced_configR\x0fadvanced_config\x125\n" +
	"\x06backup\x18\x0e \x01(\v2\x1d.yuhaiin.backup.backup_optionR\x06backup\"\x9b\x01\n" +
	"\x0fadvanced_config\x12(\n" +
	"\x0fudp_buffer_size\x18\x01 \x01(\x05R\x0fudp_buffer_size\x12,\n" +
	"\x11relay_buffer_size\x18\x02 \x01(\x05R\x11relay_buffer_size\x120\n" +
	"\x13udp_ringbuffer_size\x18\x03 \x01(\x05R\x13udp_ringbuffer_size\":\n" +
	"\fsystem_proxy\x12\x12\n" +
	"\x04http\x18\x02 \x01(\bR\x04http\x12\x16\n" +
	"\x06socks5\x18\x03 \x01(\bR\x06socks5\"\xea\x01\n" +
	"\x04info\x12\x18\n" +
	"\aversion\x18\x01 \x01(\tR\aversion\x12\x16\n" +
	"\x06commit\x18\x02 \x01(\tR\x06commit\x12\x1e\n" +
	"\n" +
	"build_time\x18\x03 \x01(\tR\n" +
	"build_time\x12\x1e\n" +
	"\n" +
	"go_version\x18\x04 \x01(\tR\n" +
	"go_version\x12\x12\n" +
	"\x04arch\x18\x05 \x01(\tR\x04arch\x12\x1a\n" +
	"\bplatform\x18\x06 \x01(\tR\bplatform\x12\x0e\n" +
	"\x02os\x18\a \x01(\tR\x02os\x12\x1a\n" +
	"\bcompiler\x18\b \x01(\tR\bcompiler\x12\x14\n" +
	"\x05build\x18\t \x03(\tR\x05build\"*\n" +
	"\x0econfig_version\x12\x18\n" +
	"\aversion\x18\x01 \x01(\x04R\aversion\",\n" +
	"\bplatform\x12 \n" +
	"\vandroid_app\x18\x01 \x01(\bR\vandroid_appB8Z.github.com/Asutorufa/yuhaiin/pkg/protos/config\x92\x03\x05\xd2>\x02\x10\x03b\beditionsp\xe8\a"

var file_config_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_config_config_proto_goTypes = []any{
	(*Setting)(nil),                // 0: yuhaiin.config.setting
	(*AdvancedConfig)(nil),         // 1: yuhaiin.config.advanced_config
	(*SystemProxy)(nil),            // 2: yuhaiin.config.system_proxy
	(*Info)(nil),                   // 3: yuhaiin.config.info
	(*ConfigVersion)(nil),          // 4: yuhaiin.config.config_version
	(*Platform)(nil),               // 5: yuhaiin.config.platform
	(*bypass.Config)(nil),          // 6: yuhaiin.bypass.config
	(*dns.DnsConfig)(nil),          // 7: yuhaiin.dns.dns_config
	(*listener.InboundConfig)(nil), // 8: yuhaiin.listener.inbound_config
	(*log.Logcat)(nil),             // 9: yuhaiin.log.logcat
	(*backup.BackupOption)(nil),    // 10: yuhaiin.backup.backup_option
}
var file_config_config_proto_depIdxs = []int32{
	2,  // 0: yuhaiin.config.setting.system_proxy:type_name -> yuhaiin.config.system_proxy
	6,  // 1: yuhaiin.config.setting.bypass:type_name -> yuhaiin.bypass.config
	7,  // 2: yuhaiin.config.setting.dns:type_name -> yuhaiin.dns.dns_config
	8,  // 3: yuhaiin.config.setting.server:type_name -> yuhaiin.listener.inbound_config
	9,  // 4: yuhaiin.config.setting.logcat:type_name -> yuhaiin.log.logcat
	4,  // 5: yuhaiin.config.setting.config_version:type_name -> yuhaiin.config.config_version
	5,  // 6: yuhaiin.config.setting.platform:type_name -> yuhaiin.config.platform
	1,  // 7: yuhaiin.config.setting.advanced_config:type_name -> yuhaiin.config.advanced_config
	10, // 8: yuhaiin.config.setting.backup:type_name -> yuhaiin.backup.backup_option
	9,  // [9:9] is the sub-list for method output_type
	9,  // [9:9] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_config_config_proto_init() }
func file_config_config_proto_init() {
	if File_config_config_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_config_config_proto_rawDesc), len(file_config_config_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_config_proto_goTypes,
		DependencyIndexes: file_config_config_proto_depIdxs,
		MessageInfos:      file_config_config_proto_msgTypes,
	}.Build()
	File_config_config_proto = out.File
	file_config_config_proto_goTypes = nil
	file_config_config_proto_depIdxs = nil
}
