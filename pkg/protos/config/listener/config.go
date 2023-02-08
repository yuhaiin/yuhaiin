package listener

import (
	"crypto/tls"
	"fmt"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var execProtocol syncmap.SyncMap[reflect.Type, func(*Opts[IsProtocol_Protocol]) (server.Server, error)]

func RegisterProtocol[T isProtocol_Protocol](wrap func(*Opts[T]) (server.Server, error)) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(p *Opts[IsProtocol_Protocol]) (server.Server, error) {
			return wrap(CovertOpts(p, func(p IsProtocol_Protocol) T { return p.(T) }))
		},
	)
}

type ProcessDumper interface {
	ProcessName(network string, src, dst proxy.Address) (string, error)
}

type Opts[T isProtocol_Protocol] struct {
	Dialer    proxy.Proxy
	DNSServer server.DNSServer
	IPv6      bool

	Protocol T
}

type IsProtocol_Protocol interface {
	isProtocol_Protocol
}

func CovertOpts[T1, T2 isProtocol_Protocol](o *Opts[T1], f func(t T1) T2) *Opts[T2] {
	return &Opts[T2]{
		Dialer:    o.Dialer,
		DNSServer: o.DNSServer,
		IPv6:      o.IPv6,
		Protocol:  f(o.Protocol),
	}
}

func CreateServer(opts *Opts[IsProtocol_Protocol]) (server.Server, error) {
	conn, ok := execProtocol.Load(reflect.TypeOf(opts.Protocol))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", opts.Protocol)
	}
	return conn(opts)
}

func ParseTLS(t *TlsConfig) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(t.GetCert(), t.GetKey())
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   t.NextProtos,
	}, nil
}
