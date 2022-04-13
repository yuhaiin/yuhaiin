package node

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func (p *Point) Conn() (r proxy.Proxy, err error) {
	r = direct.Default
	for _, v := range p.Protocols {
		r, err = Proxy(v.Protocol)(r)
		if err != nil {
			return
		}
	}

	return
}

var execProtocol syncmap.SyncMap[reflect.Type, func(isPointProtocol_Protocol) func(proxy.Proxy) (proxy.Proxy, error)]

func RegisterProtocol[T isPointProtocol_Protocol](f func(T) func(proxy.Proxy) (proxy.Proxy, error)) {
	if f == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(t isPointProtocol_Protocol) func(p proxy.Proxy) (proxy.Proxy, error) { return f(t.(T)) },
	)
}

func Proxy(p isPointProtocol_Protocol) func(proxy.Proxy) (proxy.Proxy, error) {
	if p == nil {
		return ErrConn(fmt.Errorf("value is nil: %v", p))
	}

	conn, ok := execProtocol.Load(reflect.TypeOf(p))
	if !ok {
		return ErrConn(fmt.Errorf("protocol %v is not support", p))
	}

	return conn(p)
}

func ParseTLSConfig(t *TlsConfig) *tls.Config {
	if t == nil || !t.Enable {
		return nil
	}
	//tls
	root, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("get x509 system cert pool failed: %v, create new cert pool.", err)
		root = x509.NewCertPool()
	}

	config := &tls.Config{
		ServerName: t.ServerName,
		RootCAs:    root,
		// NextProtos:             []string{"http/1.1"},
		InsecureSkipVerify: t.InsecureSkipVerify,
		// SessionTicketsDisabled: true,
		// ClientSessionCache:     tlsSessionCache,
	}

	for i := range t.CaCert {
		ok := config.RootCAs.AppendCertsFromPEM(t.CaCert[i])
		if !ok {
			log.Printf("add cert from pem failed.")
		}
	}

	return config
}

func ErrConn(err error) func(proxy.Proxy) (proxy.Proxy, error) {
	return func(proxy.Proxy) (proxy.Proxy, error) {
		return nil, err
	}
}
