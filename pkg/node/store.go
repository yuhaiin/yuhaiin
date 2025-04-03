package node

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

// ProxyEntry
//
// TODO:
// first solution:
//
//	Ref counter: make sure all parent(eg: [Set]) released before proxy close
//	Slef update: update proxy (close and recreate) when point config changed
//
// second solution:
//
//	check all using nodes(include [Set]) and close useless nodes
//
// third solution:
//
//	double reference: node <-> [Set]
type ProxyEntry struct {
	Proxy  netapi.Proxy
	Config *point.Point
	mu     sync.RWMutex
}

type ProxyStore struct {
	store  syncmap.SyncMap[string, *ProxyEntry]
	mu     sync.RWMutex
	closed atomic.Bool
}

func NewProxyStore() *ProxyStore {
	return &ProxyStore{}
}

func (p *ProxyStore) LoadOrCreate(ctx context.Context, hash string, f func() (*ProxyEntry, error)) (netapi.Proxy, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed.Load() {
		return nil, errors.New("store closed")
	}

	pp, _, err := p.store.LoadOrCreate(hash, f)
	if err != nil {
		return nil, err
	}

	pp.mu.RLock()
	defer pp.mu.RUnlock()

	if store := netapi.GetContextOrNil(ctx); store != nil {
		store.Hash = hash
		store.NodeName = pp.Config.GetName()
	}

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

func (p *ProxyStore) Refresh(po *point.Point) {
	r, ok := p.store.Load(po.GetHash())
	if !ok {
		return
	}

	r.mu.Lock()

	changed := !proto.Equal(r.Config, po)

	if !changed {
		r.mu.Unlock()
		return
	}

	if err := r.Proxy.Close(); err != nil {
		log.Error("close proxy failed", "key", po.GetHash(), "err", err)
	}
	r.Proxy = netapi.NewErrProxy(errors.New("proxy closed"))
	r.mu.Unlock()

	p.Delete(po.GetHash())
}

func (p *ProxyStore) Range(f func(key string, value *ProxyEntry) bool) {
	p.store.Range(f)
}

func (p *ProxyStore) Close() error {
	p.closed.Store(true)

	p.mu.Lock()
	defer p.mu.Unlock()

	for k := range p.store.Range {
		p.Delete(k)
	}

	return nil
}
