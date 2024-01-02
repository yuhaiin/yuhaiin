package point

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	reflect "reflect"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	protocol "github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func init() {
	RegisterProtocol(func(*protocol.Protocol_None) WrapProxy {
		return func(p netapi.Proxy) (netapi.Proxy, error) { return p, nil }
	})
}

func Dialer(p *Point) (r netapi.Proxy, err error) {
	r = InitProxy

	for _, v := range p.Protocols {
		r, err = Wrap(v.Protocol)(r)
		if err != nil {
			return
		}
	}

	return
}

type WrapProxy func(p netapi.Proxy) (netapi.Proxy, error)

var execProtocol syncmap.SyncMap[reflect.Type, func(protocol.IsProtocol_Protocol) WrapProxy]

func RegisterProtocol[T protocol.IsProtocol_Protocol](wrap func(T) WrapProxy) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(t protocol.IsProtocol_Protocol) WrapProxy { return wrap(t.(T)) },
	)
}

func Wrap(p protocol.IsProtocol_Protocol) WrapProxy {
	if p == nil {
		return ErrConn(fmt.Errorf("value is nil: %v", p))
	}

	conn, ok := execProtocol.Load(reflect.TypeOf(p))
	if !ok {
		return ErrConn(fmt.Errorf("protocol %v is not support", p))
	}

	return conn(p)
}

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

func ParseTLSConfig(t *protocol.TlsConfig) *tls.Config {
	if t == nil || !t.Enable {
		return nil
	}

	root, err := x509.SystemCertPool()
	if err != nil {
		log.Error("get x509 system cert pool failed, create new cert pool.", "err", err)
		root = x509.NewCertPool()
	}

	for i := range t.CaCert {
		ok := root.AppendCertsFromPEM(t.CaCert[i])
		if !ok {
			log.Error("add cert from pem failed.")
		}
	}
	var servername string
	if len(t.ServerNames) > 0 {
		servername = t.ServerNames[0]
	}

	return &tls.Config{
		ServerName:         servername,
		RootCAs:            root,
		NextProtos:         t.NextProtos,
		InsecureSkipVerify: t.InsecureSkipVerify,
		ClientSessionCache: tlsSessionCache,
		// SessionTicketsDisabled: true,
	}
}

func ErrConn(err error) WrapProxy {
	return func(netapi.Proxy) (netapi.Proxy, error) {
		return nil, err
	}
}

var InitProxy = netapi.NewErrProxy(errors.New("init proxy"))

func IsInitProxy(p netapi.Proxy) bool { return p == InitProxy }
