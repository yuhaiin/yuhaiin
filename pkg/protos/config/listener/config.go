package listener

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"reflect"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/exp/slog"
)

var execProtocol syncmap.SyncMap[reflect.Type, func(*Opts[IsProtocol_Protocol]) (proxy.Server, error)]

func RegisterProtocol[T isProtocol_Protocol](wrap func(*Opts[T]) (proxy.Server, error)) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(p *Opts[IsProtocol_Protocol]) (proxy.Server, error) {
			return wrap(CovertOpts(p, func(p IsProtocol_Protocol) T { return p.(T) }))
		},
	)
}

type ProcessDumper interface {
	ProcessName(network string, src, dst proxy.Address) (string, error)
}

type Opts[T isProtocol_Protocol] struct {
	IPv6 bool

	Protocol T

	DNSHandler proxy.DNSHandler
	Handler    proxy.Handler
}

type IsProtocol_Protocol interface {
	isProtocol_Protocol
}

func CovertOpts[T1, T2 isProtocol_Protocol](o *Opts[T1], f func(t T1) T2) *Opts[T2] {
	return &Opts[T2]{
		DNSHandler: o.DNSHandler,
		IPv6:       o.IPv6,
		Protocol:   f(o.Protocol),
		Handler:    o.Handler,
	}
}

func CreateServer(opts *Opts[IsProtocol_Protocol]) (proxy.Server, error) {
	conn, ok := execProtocol.Load(reflect.TypeOf(opts.Protocol))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", opts.Protocol)
	}
	return conn(opts)
}

func ParseTLS(t *TlsConfig) (*tls.Config, error) {
	if t == nil {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		Certificates: make([]tls.Certificate, 0, len(t.Certificates)),
		NextProtos:   t.NextProtos,
	}

	for _, c := range t.Certificates {
		cert, err := c.X509KeyPair()
		if err != nil {
			log.Warn("key pair failed", "cert", c.Cert, "err", err)
			continue
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	if len(t.ServerNameCertificate) == 0 {
		return tlsConfig, nil
	}

	serverNameCertificateMap := make(map[string]*tls.Certificate, len(t.ServerNameCertificate))

	for c, v := range t.ServerNameCertificate {
		cert, err := v.X509KeyPair()
		if err != nil {
			log.Warn("key pair failed", "cert", v.Cert, "err", err)
			continue
		}

		serverNameCertificateMap[c] = &cert
	}

	tlsConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for c, v := range serverNameCertificateMap {
			if strings.HasSuffix(chi.ServerName, c) {
				return v, nil
			}
		}

		if len(tlsConfig.Certificates) > 0 {
			return &tlsConfig.Certificates[rand.Intn(len(tlsConfig.Certificates))], nil
		}

		return nil, fmt.Errorf("can't find certificate for %s", chi.ServerName)
	}

	return tlsConfig, nil
}

func (c *Certificate) X509KeyPair() (tls.Certificate, error) {

	if c.CertFilePath != "" && c.KeyFilePath != "" {
		r, err := tls.LoadX509KeyPair(c.CertFilePath, c.KeyFilePath)
		if err != nil {
			log.Warn("load X509KeyPair error", slog.Any("err", err))
		} else {
			return r, nil
		}
	}

	return tls.X509KeyPair(c.Cert, c.Key)
}
