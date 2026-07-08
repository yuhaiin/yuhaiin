package register

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

func GetProtocolOneofValue(i *config.Inbound) any {
	if i == nil {
		return &config.Empty{}
	}
	switch i.WhichProtocol() {
	case config.Inbound_Http_case:
		return i.GetHttp()
	case config.Inbound_Socks5_case:
		return i.GetSocks5()
	case config.Inbound_Yuubinsya_case:
		return i.GetYuubinsya()
	case config.Inbound_Mix_case:
		return i.GetMix()
	case config.Inbound_Socks4A_case:
		return i.GetSocks4A()
	case config.Inbound_Tproxy_case:
		return i.GetTproxy()
	case config.Inbound_Redir_case:
		return i.GetRedir()
	case config.Inbound_Tun_case:
		return i.GetTun()
	case config.Inbound_ReverseHttp_case:
		return i.GetReverseHttp()
	case config.Inbound_ReverseTcp_case:
		return i.GetReverseTcp()
	case config.Inbound_None_case:
		return i.GetNone()
	default:
		return &config.Empty{}
	}
}

func GetNetworkOneofValue(i *config.Inbound) any {
	if i == nil {
		return &config.Empty{}
	}
	switch i.WhichNetwork() {
	case config.Inbound_Empty_case:
		return i.GetEmpty()
	case config.Inbound_Tcpudp_case:
		return i.GetTcpudp()
	case config.Inbound_Quic_case:
		return i.GetQuic()
	default:
		return &config.Empty{}
	}
}

func GetTransportOneofValue(i *config.Transport) any {
	if i == nil {
		return &config.Normal{}
	}
	switch i.WhichTransport() {
	case config.Transport_Normal_case:
		return i.GetNormal()
	case config.Transport_Tls_case:
		return i.GetTls()
	case config.Transport_Mux_case:
		return i.GetMux()
	case config.Transport_Http2_case:
		return i.GetHttp2()
	case config.Transport_Websocket_case:
		return i.GetWebsocket()
	case config.Transport_Reality_case:
		return i.GetReality()
	case config.Transport_TlsAuto_case:
		return i.GetTlsAuto()
	case config.Transport_HttpMock_case:
		return i.GetHttpMock()
	case config.Transport_Aead_case:
		return i.GetAead()
	case config.Transport_Proxy_case:
		return i.GetProxy()
	default:
		return &config.Normal{}
	}
}

func ParseCertificates(t *node.TlsServerConfig) []tls.Certificate {
	r := make([]tls.Certificate, 0, len(t.GetCertificates()))

	for _, c := range t.GetCertificates() {
		cert, err := X509KeyPair(c)
		if err != nil {
			log.Warn("key pair failed", "cert", c.GetCert(), "err", err)
			continue
		}

		r = append(r, cert)
	}

	if len(r) == 0 {
		return nil
	}

	return r
}

func ParseServerNameCertificate(t *node.TlsServerConfig) *trie.Trie[*tls.Certificate] {
	var searcher *trie.Trie[*tls.Certificate]

	for c, v := range t.GetServerNameCertificate() {
		if c == "" {
			continue
		}

		cert, err := X509KeyPair(v)
		if err != nil {
			log.Warn("key pair failed", "cert", v.GetCert(), "err", err)
			continue
		}

		if net.ParseIP(c) == nil && c[0] != '*' {
			c = "*." + c
		}

		if searcher == nil {
			searcher = trie.NewTrie[*tls.Certificate]()
		}

		searcher.Insert(c, &cert)
	}

	return searcher
}

func X509KeyPair(c *node.Certificate) (tls.Certificate, error) {
	if c.GetCertFilePath() != "" && c.GetKeyFilePath() != "" {
		r, err := tls.LoadX509KeyPair(c.GetCertFilePath(), c.GetKeyFilePath())
		if err != nil {
			log.Warn("load X509KeyPair error", slog.Any("err", err))
		} else {
			return r, nil
		}
	}

	return tls.X509KeyPair(c.GetCert(), c.GetKey())
}

type TlsConfigManager struct {
	t           *node.TlsServerConfig
	tlsConfig   *tls.Config
	searcher    *trie.Trie[*tls.Certificate]
	refreshTime int64
	mu          sync.Mutex
}

func NewTlsConfigManager(t *node.TlsServerConfig) *TlsConfigManager {
	tm := &TlsConfigManager{t: t}
	tm.Refresh()
	return tm
}

func (t *TlsConfigManager) Refresh() {
	if t.tlsConfig == nil {
		t.tlsConfig = &tls.Config{
			NextProtos: t.t.GetNextProtos(),
		}
	}

	t.tlsConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		t.mu.Lock()
		if (system.CheapNowNano() - t.refreshTime) > (time.Hour * 24).Nanoseconds() { // refresh every day
			t.Refresh()
		}
		t.mu.Unlock()

		if t.searcher != nil {
			addr, err := netapi.ParseAddressPort("tcp", chi.ServerName, 0)
			if err == nil {
				v, ok := t.searcher.SearchFqdn(addr)
				if ok {
					return v, nil
				}
			}
		}

		if t.tlsConfig.Certificates != nil {
			return &t.tlsConfig.Certificates[rand.IntN(len(t.tlsConfig.Certificates))], nil
		}

		return nil, fmt.Errorf("can't find certificate for %s", chi.ServerName)
	}

	t.tlsConfig.Certificates = ParseCertificates(t.t)
	t.searcher = ParseServerNameCertificate(t.t)
	t.refreshTime = system.CheapNowNano()
}

func ParseTLS(t *node.TlsServerConfig) (*tls.Config, error) {
	if t == nil {
		return nil, nil
	}

	tm := NewTlsConfigManager(t)

	return tm.tlsConfig, nil
}

var (
	networkStore   syncmap.SyncMap[reflect.Type, func(any) (netapi.Listener, error)]
	transportStore syncmap.SyncMap[reflect.Type, func(any, netapi.Listener) (netapi.Listener, error)]
	protocolStore  syncmap.SyncMap[reflect.Type, func(any, netapi.Listener, netapi.Handler) (netapi.Accepter, error)]
)

func init() {
	RegisterNetwork(func(o *config.Empty) (netapi.Listener, error) { return nil, nil })
}

func RegisterNetwork[T any](wrap func(T) (netapi.Listener, error)) {
	if wrap == nil {
		return
	}

	networkStore.Store(
		reflect.TypeOf((*T)(nil)).Elem(),
		func(p any) (netapi.Listener, error) {
			return wrap(p.(T))
		},
	)
}

func RegisterTransport[T any](wrap func(T, netapi.Listener) (netapi.Listener, error)) {
	if wrap == nil {
		return
	}

	transportStore.Store(
		reflect.TypeOf((*T)(nil)).Elem(),
		func(p any, lis netapi.Listener) (netapi.Listener, error) {
			return wrap(p.(T), lis)
		},
	)
}

func RegisterProtocol[T any](wrap func(T, netapi.Listener, netapi.Handler) (netapi.Accepter, error)) {
	if wrap == nil {
		return
	}

	protocolStore.Store(
		reflect.TypeOf((*T)(nil)).Elem(),
		func(p any, lis netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
			return wrap(p.(T), lis, handler)
		},
	)
}

func Network(config any) (netapi.Listener, error) {
	nc, ok := networkStore.Load(reflect.TypeOf(config))
	if !ok {
		return nil, fmt.Errorf("network %v is not support", config)
	}

	return nc(config)
}

func Transports(lis netapi.Listener, protocols []*config.Transport) (netapi.Listener, error) {
	var err error
	for _, protocol := range protocols {
		v := GetTransportOneofValue(protocol)

		fn, ok := transportStore.Load(reflect.TypeOf(v))
		if !ok {
			return nil, fmt.Errorf("transport %v is not support", v)
		}

		lis, err = fn(v, lis)
		if err != nil {
			return nil, err
		}
	}

	return lis, nil
}

func Protocols(lis netapi.Listener, config any, handler netapi.Handler) (netapi.Accepter, error) {
	nc, ok := protocolStore.Load(reflect.TypeOf(config))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", config)
	}

	return nc(config, lis, handler)
}

func Listen(config *config.Inbound, handler netapi.Handler) (netapi.Accepter, error) {
	lis, err := Network(GetNetworkOneofValue(config))
	if err != nil {
		return nil, err
	}

	if lis != nil {
		lis = &metricsNetworkWrapper{lis}
	}

	tl, err := Transports(lis, config.GetTransport())
	if err != nil {
		_ = lis.Close()
		return nil, err
	}

	if tl != nil {
		tl = &metricsTransportWrapper{tl}
	}

	pl, err := Protocols(tl, GetProtocolOneofValue(config), handler)
	if err != nil {
		if tl != nil {
			_ = tl.Close()
		}
		if lis != nil {
			_ = lis.Close()
		}
		return nil, err
	}

	return pl, nil
}

type metricsNetworkWrapper struct {
	netapi.Listener
}

func (m *metricsNetworkWrapper) Accept() (net.Conn, error) {
	l, err := m.Listener.Accept()
	if err != nil {
		return nil, err
	}

	metrics.Counter.AddListenerNetworkRequest()

	return l, nil
}

func (m *metricsNetworkWrapper) Close() error {
	return m.Listener.Close()
}

type metricsTransportWrapper struct {
	netapi.Listener
}

func (m *metricsTransportWrapper) Accept() (net.Conn, error) {
	l, err := m.Listener.Accept()
	if err != nil {
		return nil, err
	}

	metrics.Counter.AddListenerTransportRequest()

	return l, nil
}

func (m *metricsTransportWrapper) Close() error {
	return m.Listener.Close()
}
