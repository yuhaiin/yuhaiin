package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func GetProtocolOneofValue(i *Inbound) proto.Message {
	ref := i.ProtoReflect()
	fields := ref.Descriptor().Oneofs().ByName("protocol")
	f := ref.WhichOneof(fields)
	if f == nil {
		return &Empty{}
	}
	return ref.Get(f).Message().Interface()
}

func GetNetworkOneofValue(i *Inbound) proto.Message {
	ref := i.ProtoReflect()
	fields := ref.Descriptor().Oneofs().ByName("network")
	f := ref.WhichOneof(fields)
	if f == nil {
		return &Empty{}
	}
	return ref.Get(f).Message().Interface()
}

func GetTransportOneofValue(i *Transport) proto.Message {
	ref := i.ProtoReflect()
	fields := ref.Descriptor().Oneofs().ByName("transport")
	f := ref.WhichOneof(fields)
	if f == nil {
		return &Normal{}
	}
	return ref.Get(f).Message().Interface()
}

func (t *TlsConfig) ParseCertificates() []tls.Certificate {
	r := make([]tls.Certificate, 0, len(t.GetCertificates()))

	for _, c := range t.GetCertificates() {
		cert, err := c.X509KeyPair()
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

func (t *TlsConfig) ParseServerNameCertificate() *trie.Trie[*tls.Certificate] {
	var searcher *trie.Trie[*tls.Certificate]

	for c, v := range t.GetServerNameCertificate() {
		if c == "" {
			continue
		}

		cert, err := v.X509KeyPair()
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

func (c *Certificate) X509KeyPair() (tls.Certificate, error) {
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
	t           *TlsConfig
	tlsConfig   *tls.Config
	searcher    *trie.Trie[*tls.Certificate]
	refreshTime int64
	mu          sync.Mutex
}

func NewTlsConfigManager(t *TlsConfig) *TlsConfigManager {
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
			addr := netapi.ParseAddressPort("tcp", chi.ServerName, 0)
			ctx := netapi.WithContext(context.TODO())
			ctx.Resolver.ResolverSelf = trie.SkipResolver
			v, ok := t.searcher.Search(ctx, addr)
			if ok {
				return v, nil
			}
		}

		if t.tlsConfig.Certificates != nil {
			return &t.tlsConfig.Certificates[rand.IntN(len(t.tlsConfig.Certificates))], nil
		}

		return nil, fmt.Errorf("can't find certificate for %s", chi.ServerName)
	}

	t.tlsConfig.Certificates = t.t.ParseCertificates()
	t.searcher = t.t.ParseServerNameCertificate()
	t.refreshTime = system.CheapNowNano()
}

func ParseTLS(t *TlsConfig) (*tls.Config, error) {
	if t == nil {
		return nil, nil
	}

	tm := NewTlsConfigManager(t)

	return tm.tlsConfig, nil
}

var (
	networkStore   syncmap.SyncMap[protoreflect.FullName, func(proto.Message) (netapi.Listener, error)]
	transportStore syncmap.SyncMap[protoreflect.FullName, func(proto.Message, netapi.Listener) (netapi.Listener, error)]
	protocolStore  syncmap.SyncMap[protoreflect.FullName, func(proto.Message, netapi.Listener, netapi.Handler) (netapi.Accepter, error)]
)

func init() {
	file_config_listener_listener_proto_init()
	RegisterNetwork(func(o *Empty) (netapi.Listener, error) { return nil, nil })
}

func RegisterNetwork[T proto.Message](wrap func(T) (netapi.Listener, error)) {
	if wrap == nil {
		return
	}

	ttt := *new(T)
	tt := ttt.ProtoReflect().Descriptor()

	networkStore.Store(
		tt.FullName(),
		func(p proto.Message) (netapi.Listener, error) {
			return wrap(p.(T))
		},
	)
}

func RegisterTransport[T proto.Message](wrap func(T, netapi.Listener) (netapi.Listener, error)) {
	if wrap == nil {
		return
	}

	ttt := *new(T)
	tt := ttt.ProtoReflect().Descriptor()

	transportStore.Store(
		tt.FullName(),
		func(p proto.Message, lis netapi.Listener) (netapi.Listener, error) {
			return wrap(p.(T), lis)
		},
	)
}

func RegisterProtocol[T proto.Message](wrap func(T, netapi.Listener, netapi.Handler) (netapi.Accepter, error)) {
	if wrap == nil {
		return
	}

	ttt := *new(T)
	tt := ttt.ProtoReflect().Descriptor()

	protocolStore.Store(
		tt.FullName(),
		func(p proto.Message, lis netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
			return wrap(p.(T), lis, handler)
		},
	)
}

func Network(config proto.Message) (netapi.Listener, error) {
	nc, ok := networkStore.Load(config.ProtoReflect().Descriptor().FullName())
	if !ok {
		return nil, fmt.Errorf("network %v is not support", config)
	}

	return nc(config)
}

func Transports(lis netapi.Listener, protocols []*Transport) (netapi.Listener, error) {
	var err error
	for _, v := range protocols {
		fn, ok := transportStore.Load(v.ProtoReflect().Descriptor().FullName())
		if !ok {
			return nil, fmt.Errorf("transport %v is not support", GetTransportOneofValue(v))
		}

		lis, err = fn(GetTransportOneofValue(v), lis)
		if err != nil {
			return nil, err
		}
	}

	return lis, nil
}

func Protocols(lis netapi.Listener, config proto.Message, handler netapi.Handler) (netapi.Accepter, error) {
	nc, ok := protocolStore.Load(config.ProtoReflect().Descriptor().FullName())
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", config)
	}

	return nc(config, lis, handler)
}

func Listen(config *Inbound, handler netapi.Handler) (netapi.Accepter, error) {
	lis, err := Network(GetNetworkOneofValue(config))
	if err != nil {
		return nil, err
	}

	tl, err := Transports(lis, config.GetTransport())
	if err != nil {
		_ = lis.Close()
		return nil, err
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
