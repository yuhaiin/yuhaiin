package node

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type WrapProxy func(p proxy.Proxy) (proxy.Proxy, error)

var execProtocol syncmap.SyncMap[reflect.Type, func(isProtocol_Protocol) WrapProxy]

func RegisterProtocol[T isProtocol_Protocol](wrap func(T) WrapProxy) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(t isProtocol_Protocol) WrapProxy { return wrap(t.(T)) },
	)
}

func Wrap(p isProtocol_Protocol) WrapProxy {
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

func ParseTLSConfig(t *TlsConfig) *tls.Config {
	if t == nil || !t.Enable {
		return nil
	}
	//tls
	root, err := x509.SystemCertPool()
	if err != nil {
		log.Errorf("get x509 system cert pool failed: %v, create new cert pool.", err)
		root = x509.NewCertPool()
	}

	config := &tls.Config{
		ServerName: t.ServerName,
		RootCAs:    root,
		// NextProtos:             []string{"http/1.1"},
		InsecureSkipVerify: t.InsecureSkipVerify,
		// SessionTicketsDisabled: true,
		ClientSessionCache: tlsSessionCache,
	}

	for i := range t.CaCert {
		ok := config.RootCAs.AppendCertsFromPEM(t.CaCert[i])
		if !ok {
			log.Errorf("add cert from pem failed.")
		}
	}

	return config
}

func ErrConn(err error) WrapProxy {
	return func(proxy.Proxy) (proxy.Proxy, error) {
		return nil, err
	}
}
