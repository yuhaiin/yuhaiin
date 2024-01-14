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

var execProtocol syncmap.SyncMap[reflect.Type, func(isProtocol_Protocol) (netapi.ProtocolServer, error)]

func RegisterProtocol[T isProtocol_Protocol](wrap func(T) (netapi.ProtocolServer, error)) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(p isProtocol_Protocol) (netapi.ProtocolServer, error) {
			return wrap(p.(T))
		},
	)
}

func CreateServer(opts isProtocol_Protocol) (netapi.ProtocolServer, error) {
	conn, ok := execProtocol.Load(reflect.TypeOf(opts))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", opts)
	}
	return conn(opts)
}

type ProcessDumper interface {
	ProcessName(network string, src, dst netapi.Address) (string, error)
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

var networkStore syncmap.SyncMap[reflect.Type, func(isInbound_Network) (netapi.Listener, error)]

func init() {
	RegisterNetwork(func(o *Inbound_Empty) (netapi.Listener, error) { return nil, nil })
}

func RegisterNetwork[T isInbound_Network](wrap func(T) (netapi.Listener, error)) {
	if wrap == nil {
		return
	}

	var z T
	networkStore.Store(
		reflect.TypeOf(z),
		func(p isInbound_Network) (netapi.Listener, error) {
			return wrap(p.(T))
		},
	)
}

func Network(config isInbound_Network) (netapi.Listener, error) {
	nc, ok := networkStore.Load(reflect.TypeOf(config))
	if !ok {
		return nil, fmt.Errorf("network %v is not support", config)
	}

	return nc(config)
}

var transportStore syncmap.SyncMap[reflect.Type, func(isTransport_Transport) func(netapi.Listener) (netapi.Listener, error)]

func RegisterTransport[T isTransport_Transport](wrap func(T) func(netapi.Listener) (netapi.Listener, error)) {
	if wrap == nil {
		return
	}

	var z T
	transportStore.Store(
		reflect.TypeOf(z),
		func(p isTransport_Transport) func(netapi.Listener) (netapi.Listener, error) {
			return wrap(p.(T))
		},
	)
}

func Transports(lis netapi.Listener, protocols []*Transport) (netapi.Listener, error) {
	var err error
	for _, v := range protocols {
		fn, ok := transportStore.Load(reflect.TypeOf(v.Transport))
		if !ok {
			return nil, fmt.Errorf("transport %v is not support", v.Transport)
		}

		lis, err = fn(v.Transport)(lis)
		if err != nil {
			return nil, err
		}
	}

	return lis, nil
}

func ErrorTransportFunc(err error) func(netapi.Listener) (netapi.Listener, error) {
	return func(ii netapi.Listener) (netapi.Listener, error) {
		return nil, err
	}
}

var protocolStore syncmap.SyncMap[reflect.Type, func(isInbound_Protocol) func(netapi.Listener) (netapi.ProtocolServer, error)]

func RegisterProtocol2[T isInbound_Protocol](wrap func(T) func(netapi.Listener) (netapi.ProtocolServer, error)) {
	if wrap == nil {
		return
	}

	var z T
	protocolStore.Store(
		reflect.TypeOf(z),
		func(p isInbound_Protocol) func(netapi.Listener) (netapi.ProtocolServer, error) {
			return wrap(p.(T))
		},
	)
}

func Protocols(lis netapi.Listener, config isInbound_Protocol) (netapi.ProtocolServer, error) {
	nc, ok := protocolStore.Load(reflect.TypeOf(config))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", config)
	}

	return nc(config)(lis)
}

func Listen(config *Inbound) (netapi.ProtocolServer, error) {
	lis, err := Network(config.Network)
	if err != nil {
		return nil, err
	}

	tl, err := Transports(lis, config.Transport)
	if err != nil {
		_ = lis.Close()
		return nil, err
	}

	pl, err := Protocols(tl, config.Protocol)
	if err != nil {
		_ = tl.Close()
		_ = lis.Close()
		return nil, err
	}

	return pl, nil
}
