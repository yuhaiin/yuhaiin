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
