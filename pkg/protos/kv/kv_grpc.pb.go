// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.2
// source: kv/kv.proto

// this is for android multiple process access bboltdb only

package kv

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Kvstore_Get_FullMethodName    = "/yuhaiin.kvstore.kvstore/Get"
	Kvstore_Set_FullMethodName    = "/yuhaiin.kvstore.kvstore/Set"
	Kvstore_Delete_FullMethodName = "/yuhaiin.kvstore.kvstore/Delete"
	Kvstore_Range_FullMethodName  = "/yuhaiin.kvstore.kvstore/Range"
	Kvstore_Ping_FullMethodName   = "/yuhaiin.kvstore.kvstore/Ping"
)

// KvstoreClient is the client API for Kvstore service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type KvstoreClient interface {
	Get(ctx context.Context, in *Element, opts ...grpc.CallOption) (*Element, error)
	Set(ctx context.Context, in *Element, opts ...grpc.CallOption) (*emptypb.Empty, error)
	Delete(ctx context.Context, in *Keys, opts ...grpc.CallOption) (*emptypb.Empty, error)
	Range(ctx context.Context, in *Element, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Element], error)
	Ping(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type kvstoreClient struct {
	cc grpc.ClientConnInterface
}

func NewKvstoreClient(cc grpc.ClientConnInterface) KvstoreClient {
	return &kvstoreClient{cc}
}

func (c *kvstoreClient) Get(ctx context.Context, in *Element, opts ...grpc.CallOption) (*Element, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Element)
	err := c.cc.Invoke(ctx, Kvstore_Get_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *kvstoreClient) Set(ctx context.Context, in *Element, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Kvstore_Set_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *kvstoreClient) Delete(ctx context.Context, in *Keys, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Kvstore_Delete_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *kvstoreClient) Range(ctx context.Context, in *Element, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Element], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Kvstore_ServiceDesc.Streams[0], Kvstore_Range_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Element, Element]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Kvstore_RangeClient = grpc.ServerStreamingClient[Element]

func (c *kvstoreClient) Ping(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Kvstore_Ping_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KvstoreServer is the server API for Kvstore service.
// All implementations must embed UnimplementedKvstoreServer
// for forward compatibility.
type KvstoreServer interface {
	Get(context.Context, *Element) (*Element, error)
	Set(context.Context, *Element) (*emptypb.Empty, error)
	Delete(context.Context, *Keys) (*emptypb.Empty, error)
	Range(*Element, grpc.ServerStreamingServer[Element]) error
	Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
	mustEmbedUnimplementedKvstoreServer()
}

// UnimplementedKvstoreServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedKvstoreServer struct{}

func (UnimplementedKvstoreServer) Get(context.Context, *Element) (*Element, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedKvstoreServer) Set(context.Context, *Element) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Set not implemented")
}
func (UnimplementedKvstoreServer) Delete(context.Context, *Keys) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedKvstoreServer) Range(*Element, grpc.ServerStreamingServer[Element]) error {
	return status.Errorf(codes.Unimplemented, "method Range not implemented")
}
func (UnimplementedKvstoreServer) Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ping not implemented")
}
func (UnimplementedKvstoreServer) mustEmbedUnimplementedKvstoreServer() {}
func (UnimplementedKvstoreServer) testEmbeddedByValue()                 {}

// UnsafeKvstoreServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KvstoreServer will
// result in compilation errors.
type UnsafeKvstoreServer interface {
	mustEmbedUnimplementedKvstoreServer()
}

func RegisterKvstoreServer(s grpc.ServiceRegistrar, srv KvstoreServer) {
	// If the following call pancis, it indicates UnimplementedKvstoreServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Kvstore_ServiceDesc, srv)
}

func _Kvstore_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Element)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KvstoreServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Kvstore_Get_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KvstoreServer).Get(ctx, req.(*Element))
	}
	return interceptor(ctx, in, info, handler)
}

func _Kvstore_Set_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Element)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KvstoreServer).Set(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Kvstore_Set_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KvstoreServer).Set(ctx, req.(*Element))
	}
	return interceptor(ctx, in, info, handler)
}

func _Kvstore_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Keys)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KvstoreServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Kvstore_Delete_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KvstoreServer).Delete(ctx, req.(*Keys))
	}
	return interceptor(ctx, in, info, handler)
}

func _Kvstore_Range_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Element)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(KvstoreServer).Range(m, &grpc.GenericServerStream[Element, Element]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Kvstore_RangeServer = grpc.ServerStreamingServer[Element]

func _Kvstore_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KvstoreServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Kvstore_Ping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KvstoreServer).Ping(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

// Kvstore_ServiceDesc is the grpc.ServiceDesc for Kvstore service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Kvstore_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "yuhaiin.kvstore.kvstore",
	HandlerType: (*KvstoreServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _Kvstore_Get_Handler,
		},
		{
			MethodName: "Set",
			Handler:    _Kvstore_Set_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _Kvstore_Delete_Handler,
		},
		{
			MethodName: "Ping",
			Handler:    _Kvstore_Ping_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Range",
			Handler:       _Kvstore_Range_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "kv/kv.proto",
}