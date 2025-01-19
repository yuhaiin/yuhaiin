package register

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	protocol "github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
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
	RegisterPoint(func(*protocol.None) WrapProxy {
		return func(p netapi.Proxy) (netapi.Proxy, error) { return p, nil }
	})
}

func Dialer(p *point.Point) (r netapi.Proxy, err error) {
	r = bootstrapProxy

	for _, v := range p.GetProtocols() {
		r, err = Wrap(GetPointValue(v))(r)
		if err != nil {
			return
		}
	}

	return
}

type WrapProxy func(p netapi.Proxy) (netapi.Proxy, error)

var execProtocol syncmap.SyncMap[protoreflect.FullName, func(proto.Message) WrapProxy]

func RegisterPoint[T proto.Message](wrap func(T) WrapProxy) {
	if wrap == nil {
		return
	}

	execProtocol.Store(
		(*new(T)).ProtoReflect().Descriptor().FullName(),
		func(t proto.Message) WrapProxy { return wrap(t.(T)) },
	)
}

func Wrap(p proto.Message) WrapProxy {
	if p == nil {
		return ErrConn(fmt.Errorf("value is nil: %v", p))
	}

	conn, ok := execProtocol.Load(p.ProtoReflect().Descriptor().FullName())
	if !ok {
		return ErrConn(fmt.Errorf("protocol %v is not support", p))
	}

	return conn(p)
}

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

func ParseTLSConfig(t *protocol.TlsConfig) *tls.Config {
	if t == nil || !t.GetEnable() {
		return nil
	}

	root, err := x509.SystemCertPool()
	if err != nil {
		log.Error("get x509 system cert pool failed, create new cert pool.", "err", err)
		root = x509.NewCertPool()
	}

	for i := range t.GetCaCert() {
		ok := root.AppendCertsFromPEM(t.GetCaCert()[i])
		if !ok {
			log.Error("add cert from pem failed.")
		}
	}

	var servername string
	if len(t.GetServerNames()) > 0 {
		servername = t.GetServerNames()[0]
	}

	echConfig := t.GetEchConfig()
	if len(echConfig) == 0 {
		echConfig = nil
	}

	return &tls.Config{
		ServerName:                     servername,
		RootCAs:                        root,
		NextProtos:                     t.GetNextProtos(),
		InsecureSkipVerify:             t.GetInsecureSkipVerify(),
		ClientSessionCache:             tlsSessionCache,
		EncryptedClientHelloConfigList: echConfig,
		// SessionTicketsDisabled: true,
	}
}

func ErrConn(err error) WrapProxy {
	return func(netapi.Proxy) (netapi.Proxy, error) {
		return nil, err
	}
}

var bootstrapProxy = netapi.NewErrProxy(errors.New("bootstrap proxy"))

func IsBootstrap(p netapi.Proxy) bool { return p == bootstrapProxy }

func SetBootstrap(p netapi.Proxy) {
	if p == nil {
		return
	}

	bootstrapProxy = p
}
