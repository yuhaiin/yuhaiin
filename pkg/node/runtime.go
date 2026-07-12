package node

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"sync"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

// NodeRuntime owns node persistence and the runtime proxy cache.
//
// It also implements the route dialer and node HTTP controller contracts so
// callers do not need a second manager/controller wrapper.
type NodeRuntime struct {
	path string

	mu      sync.Mutex
	sqlite  *storagesqlite.Store
	nodes   *plainstore.NodeStore
	closed  bool
	proxies *ProxyStore
}

func NewNodeRuntime(path string) *NodeRuntime {
	return &NodeRuntime{
		path:    path,
		proxies: NewProxyStore(),
	}
}

func (r *NodeRuntime) openNodes(ctx context.Context) (*plainstore.NodeStore, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("node runtime is closed")
	}
	if r.nodes != nil {
		return r.nodes, nil
	}

	sqliteStore, err := storagesqlite.Open(ctx, r.path)
	if err != nil {
		return nil, fmt.Errorf("open node runtime store failed: %w", err)
	}
	r.sqlite = sqliteStore
	r.nodes = plainstore.NewNodeStore(sqliteStore.DB())
	return r.nodes, nil
}

func (r *NodeRuntime) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	sqliteStore := r.sqlite
	r.sqlite = nil
	r.nodes = nil
	r.mu.Unlock()

	err := r.proxies.Close()
	if sqliteStore != nil {
		err = errors.Join(err, sqliteStore.Close())
	}
	return err
}

func (r *NodeRuntime) Save(ctx context.Context, node contractnode.Node) (contractnode.Node, error) {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return contractnode.Node{}, err
	}
	node.Origin = "manual"
	if err := nodes.Save(ctx, node, 0); err != nil {
		return contractnode.Node{}, err
	}
	r.proxies.Delete(node.ID)
	return node, nil
}

func (r *NodeRuntime) ReplaceRemoteContractNodes(ctx context.Context, group string, points []contractnode.Node) error {
	for _, point := range points {
		if point.ID != "" {
			r.proxies.Delete(point.ID)
		}
	}
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	if err := nodes.ReplaceRemote(ctx, group, points, 0); err != nil {
		return err
	}
	return r.clearIdleProxies(ctx, nodes)
}

func (r *NodeRuntime) Remove(ctx context.Context, id string) error {
	r.proxies.Delete(id)
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	if err := nodes.Delete(ctx, id); err != nil && !errors.Is(err, plainstore.ErrNotFound) {
		return err
	}
	return r.clearIdleProxies(ctx, nodes)
}

func (r *NodeRuntime) Use(ctx context.Context, id string) error {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	if err := nodes.Use(ctx, id); err != nil {
		return err
	}
	return r.clearIdleProxies(ctx, nodes)
}

func (r *NodeRuntime) AddContractTag(ctx context.Context, tag, kind, target string) error {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	if err := nodes.AddTag(ctx, tag, kind, target); err != nil {
		return err
	}
	return r.clearIdleProxies(ctx, nodes)
}

func (r *NodeRuntime) DeleteTag(ctx context.Context, tag string) error {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	if err := nodes.DeleteTag(ctx, tag); err != nil {
		return err
	}
	return r.clearIdleProxies(ctx, nodes)
}

func (r *NodeRuntime) clearIdleProxies(ctx context.Context, nodes *plainstore.NodeStore) error {
	ids, err := nodes.UsingIDs(ctx)
	if err != nil {
		return err
	}
	used := set.NewSet[string]()
	for _, id := range ids {
		used.Push(id)
	}
	for key := range r.proxies.Range {
		if !used.Has(key) {
			r.proxies.Delete(key)
		}
	}
	return nil
}

func (r *NodeRuntime) getUsingPoints() *set.Set[string] {
	nodes, err := r.openNodes(context.Background())
	if err != nil {
		return set.NewSet[string]()
	}
	ids, err := nodes.UsingIDs(context.Background())
	if err != nil {
		return set.NewSet[string]()
	}
	used := set.NewSet[string]()
	for _, id := range ids {
		used.Push(id)
	}
	return used
}

func (r *NodeRuntime) Selected(ctx context.Context) (contractnode.Selection, error) {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return contractnode.Selection{}, err
	}
	tcp, tcpOK, err := nodes.Selected(ctx, true)
	if err != nil {
		return contractnode.Selection{}, err
	}
	udp, udpOK, err := nodes.Selected(ctx, false)
	if err != nil {
		return contractnode.Selection{}, err
	}
	var out contractnode.Selection
	if tcpOK {
		out.TCP = &tcp
	}
	if udpOK {
		out.UDP = &udp
	}
	return out, nil
}

func (r *NodeRuntime) Active(context.Context) ([]contractnode.Node, error) {
	var items []contractnode.Node
	r.proxies.Range(func(_ string, value *ProxyEntry) bool {
		if value == nil {
			return true
		}
		value.mu.RLock()
		defer value.mu.RUnlock()
		if value.ContractConfig != nil {
			items = append(items, *value.ContractConfig)
		}
		return true
	})
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

func (r *NodeRuntime) CloseNode(_ context.Context, id string) error {
	if id != "" {
		r.proxies.Delete(id)
	}
	return nil
}

func (r *NodeRuntime) Latency(ctx context.Context, id string, req contractnode.LatencyRequest) (contractnode.LatencyResponse, error) {
	proxy, err := r.GetDialerByID(ctx, id)
	if err != nil {
		return contractnode.LatencyResponse{}, err
	}
	return latency.Latency(req, &latencyDialer{Proxy: proxy, ipv6: req.IPv6})
}

func (r *NodeRuntime) getContractDialer(ctx context.Context, id string, load func() (contractnode.Node, error)) (netapi.Proxy, error) {
	if id == "" {
		return nil, fmt.Errorf("hash is empty")
	}
	return r.proxies.LoadOrCreate(ctx, id, func() (*ProxyEntry, error) {
		node, err := load()
		if err != nil {
			return nil, err
		}
		proxy, err := register.ContractDialer(node)
		if err != nil {
			return nil, err
		}
		return &ProxyEntry{Proxy: proxy, ContractConfig: &node, Name: node.Name}, nil
	})
}

func (r *NodeRuntime) Get(ctx context.Context, network, mode, tag string) (netapi.Proxy, error) {
	connection := netapi.GetContext(ctx)
	if tag != "" {
		connection.SetTag(tag)
		id, err := r.tagConn(ctx, tag)
		if err != nil {
			return nil, err
		}
		if id != "" {
			if proxy, err := r.GetDialerByID(ctx, id); err == nil {
				return proxy, nil
			}
		}
	}

	switch mode {
	case "direct":
		return direct.Default, nil
	case "block":
		metrics.Counter.AddBlockConnection(mode)
		return reject.Default, nil
	}
	if len(network) < 3 {
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	nodes, err := r.openNodes(ctx)
	if err != nil {
		return nil, err
	}
	switch network[:3] {
	case "tcp":
		selected, ok, err := nodes.Selected(ctx, true)
		if err == nil && ok {
			return r.getContractDialer(ctx, selected.ID, func() (contractnode.Node, error) { return selected, nil })
		}
	case "udp":
		selected, ok, err := nodes.Selected(ctx, false)
		if err == nil && ok {
			return r.getContractDialer(ctx, selected.ID, func() (contractnode.Node, error) { return selected, nil })
		}
	default:
		return nil, fmt.Errorf("invalid network: %s", network)
	}
	return nil, fmt.Errorf("selected %s node not found", network[:3])
}

func (r *NodeRuntime) GetDialerByID(ctx context.Context, id string) (netapi.Proxy, error) {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return nil, err
	}
	node, err := nodes.Get(ctx, id)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, fmt.Errorf("node not found")
	}
	if err != nil {
		return nil, err
	}
	return r.getContractDialer(ctx, id, func() (contractnode.Node, error) { return node, nil })
}

func (r *NodeRuntime) tagConn(ctx context.Context, tag string) (string, error) {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return "", err
	}
	for {
		value, ok, err := nodes.GetTag(ctx, tag)
		if err != nil {
			return "", err
		}
		if !ok || len(value.TargetIDs) == 0 {
			return "", nil
		}
		if value.Kind == "mirror" {
			if tag == value.TargetIDs[0] {
				return "", nil
			}
			tag = value.TargetIDs[0]
			continue
		}
		return value.TargetIDs[rand.IntN(len(value.TargetIDs))], nil
	}
}

type latencyDialer struct {
	netapi.Proxy
	ipv6 bool
}

func (d *latencyDialer) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	return d.Proxy.Conn(withResolverMode(ctx, d.ipv6), address)
}

func (d *latencyDialer) PacketConn(ctx context.Context, address netapi.Address) (net.PacketConn, error) {
	return d.Proxy.PacketConn(withResolverMode(ctx, d.ipv6), address)
}

func withResolverMode(ctx context.Context, ipv6 bool) context.Context {
	netctx := netapi.GetContext(ctx)
	if ipv6 {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv6)
	} else {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
	}
	return netctx
}
