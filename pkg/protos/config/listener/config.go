package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"reflect"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var execProtocol syncmap.SyncMap[reflect.Type, func(*Opts[IsProtocol_Protocol]) (netapi.Server, error)]

func RegisterProtocol[T isProtocol_Protocol](wrap func(*Opts[T]) (netapi.Server, error)) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(p *Opts[IsProtocol_Protocol]) (netapi.Server, error) {
			return wrap(CovertOpts(p, func(p IsProtocol_Protocol) T { return p.(T) }))
		},
	)
}

type ProcessDumper interface {
	ProcessName(network string, src, dst netapi.Address) (string, error)
}

type Opts[T isProtocol_Protocol] struct {
	IPv6 bool

	Protocol T

	DNSHandler netapi.DNSHandler
	Handler    netapi.Handler
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

func CreateServer(opts *Opts[IsProtocol_Protocol]) (netapi.Server, error) {
	conn, ok := execProtocol.Load(reflect.TypeOf(opts.Protocol))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", opts.Protocol)
	}
	return conn(opts)
}

func (t *TlsConfig) ParseCertificates() []tls.Certificate {
	r := make([]tls.Certificate, 0, len(t.Certificates))

	for _, c := range t.Certificates {
		cert, err := c.X509KeyPair()
		if err != nil {
			log.Warn("key pair failed", "cert", c.Cert, "err", err)
			continue
		}

		r = append(r, cert)
	}

	if len(r) == 0 {
		return nil
	}

	return r
}

func (t *TlsConfig) ParseServerNameCertificate() *mapper.Combine[*tls.Certificate] {
	var searcher *mapper.Combine[*tls.Certificate]

	for c, v := range t.ServerNameCertificate {
		if c == "" {
			continue
		}

		cert, err := v.X509KeyPair()
		if err != nil {
			log.Warn("key pair failed", "cert", v.Cert, "err", err)
			continue
		}

		if net.ParseIP(c) == nil && c[0] != '*' {
			c = "*." + c
		}

		if searcher == nil {
			searcher = mapper.NewMapper[*tls.Certificate]()
		}

		searcher.Insert(c, &cert)
	}

	return searcher
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

type TlsConfigManager struct {
	t           *TlsConfig
	tlsConfig   *tls.Config
	searcher    *mapper.Combine[*tls.Certificate]
	refreshTime time.Time
}

func NewTlsConfigManager(t *TlsConfig) *TlsConfigManager {
	tm := &TlsConfigManager{
		t:           t,
		searcher:    t.ParseServerNameCertificate(),
		refreshTime: time.Now(),
	}

	tm.Refresh()

	return tm
}

func (t *TlsConfigManager) Refresh() {
	if t.tlsConfig == nil {
		t.tlsConfig = &tls.Config{
			NextProtos: t.t.NextProtos,
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if t.refreshTime.Add(time.Hour * 24).After(time.Now()) {
					t.Refresh()
				}

				if t.searcher != nil {
					addr := netapi.ParseAddressPort(statistic.Type_tcp, chi.ServerName, netapi.EmptyPort)
					addr.WithResolver(mapper.SkipResolver, false)
					v, ok := t.searcher.Search(context.TODO(), addr)
					if ok {
						return v, nil
					}
				}

				if t.tlsConfig.Certificates != nil {
					return &t.tlsConfig.Certificates[rand.Intn(len(t.tlsConfig.Certificates))], nil
				}

				return nil, fmt.Errorf("can't find certificate for %s", chi.ServerName)
			},
		}
	}

	t.tlsConfig.Certificates = t.t.ParseCertificates()
	t.searcher = t.t.ParseServerNameCertificate()
}

func ParseTLS(t *TlsConfig) (*tls.Config, error) {
	if t == nil {
		return nil, nil
	}

	tm := NewTlsConfigManager(t)

	return tm.tlsConfig, nil
}

func (m *Protocol_Mix) HTTP() *Protocol_Http {
	return &Protocol_Http{
		Http: &Http{
			Host:     m.Mix.Host,
			Username: m.Mix.Username,
			Password: m.Mix.Password,
		},
	}
}

func (m *Protocol_Mix) SOCKS5() *Protocol_Socks5 {
	return &Protocol_Socks5{
		Socks5: &Socks5{
			Host:     m.Mix.Host,
			Username: m.Mix.Username,
			Password: m.Mix.Password,
		},
	}
}

func (m *Protocol_Mix) SOCKS4A() *Protocol_Socks4A {
	return &Protocol_Socks4A{
		Socks4A: &Socks4A{
			Host:     m.Mix.Host,
			Username: m.Mix.Username,
		},
	}
}
