package node

import (
	"errors"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

type ProxyEntry struct {
	mu     sync.RWMutex
	Config *point.Point
	Proxy  netapi.Proxy
}

type ProxyStore struct {
	store syncmap.SyncMap[string, *ProxyEntry]
}

func NewProxyStore() *ProxyStore {
	return &ProxyStore{}
}

func (p *ProxyStore) LoadOrCreate(hash string, f func() (*ProxyEntry, error)) (netapi.Proxy, error) {
	pp, _, err := p.store.LoadOrCreate(hash, f)
	if err != nil {
		return nil, err
	}

	pp.mu.RLock()
	defer pp.mu.RUnlock()

	return pp.Proxy, err
}

func (p *ProxyStore) Delete(hash string) {
	r, ok := p.store.LoadAndDelete(hash)
	if !ok {
		return
	}

	r.mu.Lock()
	if err := r.Proxy.Close(); err != nil {
		log.Error("close proxy failed", "key", hash, "err", err)
	}
	r.Proxy = netapi.NewErrProxy(errors.New("proxy closed"))
	r.mu.Unlock()
}

func (p *ProxyStore) RefreshNode(po *point.Point) {
	r, ok := p.store.Load(po.GetHash())
	if !ok {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	changed := !proto.Equal(r.Config, po)

	if !changed {
		return
	}

	if err := r.Proxy.Close(); err != nil {
		log.Error("close proxy failed", "key", po.GetHash(), "err", err)
	}
	r.Proxy = netapi.NewErrProxy(errors.New("proxy closed"))
	p.store.Delete(po.GetHash())
}

func (p *ProxyStore) Range(f func(key string, value *ProxyEntry) bool) {
	p.store.Range(f)
}
