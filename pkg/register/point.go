package register

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func GetPointValue(i *protocol.Protocol) proto.Message {
	ref := i.ProtoReflect()
	fields := ref.Descriptor().Oneofs().ByName("protocol")
	f := ref.WhichOneof(fields)
	if f == nil {
		return &protocol.None{}
	}
	return ref.Get(f).Message().Interface()
}

func init() {
	RegisterPoint(func(_ *protocol.None, p netapi.Proxy) (netapi.Proxy, error) {
		return p, nil
	})
	RegisterPoint(func(_ *protocol.BootstrapDnsWarp, p netapi.Proxy) (netapi.Proxy, error) {
		return NewBootstrapDnsWarp(p), nil
	})

	RegisterPoint(func(ns *protocol.NetworkSplit, p netapi.Proxy) (netapi.Proxy, error) {
		if ns.GetTcp().WhichProtocol() == protocol.Protocol_NetworkSplit_case {
			return nil, fmt.Errorf("nested network split is not supported")
		}

		if ns.GetUdp().WhichProtocol() == protocol.Protocol_NetworkSplit_case {
			return nil, fmt.Errorf("nested network split is not supported")
		}

		tcp, err := Wrap(GetPointValue(ns.GetTcp()), p)
		if err != nil {
			return nil, err
		}

		udp, err := Wrap(GetPointValue(ns.GetUdp()), p)
		if err != nil {
			_ = tcp.Close()
			return nil, err
		}

		return &networkSplit{tcp: tcp, udp: udp, Proxy: p}, nil
	})
}

var _ netapi.Proxy = (*networkSplit)(nil)

type networkSplit struct {
	tcp netapi.Proxy
	udp netapi.Proxy
	netapi.Proxy
}

func (n *networkSplit) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return n.tcp.Conn(ctx, addr)
}

func (n *networkSplit) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return n.udp.PacketConn(ctx, addr)
}

func (n *networkSplit) Close() error {
	var err error
	if er := n.tcp.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := n.udp.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := n.Proxy.Close(); er != nil {
		err = errors.Join(err, er)
	}
	return err
}

func Dialer(p *point.Point) (r netapi.Proxy, err error) {
	r = bootstrapProxy

	for _, v := range p.GetProtocols() {
		r, err = Wrap(GetPointValue(v), r)
		if err != nil {
			return
		}
	}

	return
}

type WrapProxy[T proto.Message] func(t T, p netapi.Proxy) (netapi.Proxy, error)

var execProtocol syncmap.SyncMap[protoreflect.FullName, WrapProxy[proto.Message]]

func RegisterPoint[T proto.Message](wrap func(T, netapi.Proxy) (netapi.Proxy, error)) {
	if wrap == nil {
		return
	}

	execProtocol.Store(
		(*new(T)).ProtoReflect().Descriptor().FullName(),
		func(t proto.Message, p netapi.Proxy) (netapi.Proxy, error) { return wrap(t.(T), p) },
	)
}

func Wrap(p proto.Message, x netapi.Proxy) (netapi.Proxy, error) {
	if p == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	conn, ok := execProtocol.Load(p.ProtoReflect().Descriptor().FullName())
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", p)
	}

	return conn(p, x)
}

var bootstrapProxy = netapi.NewErrProxy(errors.New("bootstrap proxy"))

func IsBootstrap(p netapi.Proxy) bool { return p == bootstrapProxy }

func SetBootstrap(p netapi.Proxy) {
	if p == nil {
		return
	}

	bootstrapProxy = p
}

type bootstrapDnsWarp struct {
	netapi.Proxy
}

func NewBootstrapDnsWarp(p netapi.Proxy) netapi.Proxy {
	return &bootstrapDnsWarp{Proxy: p}
}

func (b *bootstrapDnsWarp) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return b.Proxy.Conn(netapi.WithContext(ctx), addr)
}

func (b *bootstrapDnsWarp) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return b.Proxy.PacketConn(netapi.WithContext(ctx), addr)
}
