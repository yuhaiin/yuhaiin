package node

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/credential"
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
	credentialMu       sync.Mutex
	credentials        credential.Resolver
	credentialVersions map[string]string
	path               string

	mu       sync.Mutex
	sqlite   *storagesqlite.Store
	nodes    *plainstore.NodeStore
	closed   bool
	proxies  *ProxyStore
	observer *nodeObserver
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
	observer, err := newNodeObserver(ctx, sqliteStore.DB())
	if err != nil {
		_ = sqliteStore.Close()
		return nil, fmt.Errorf("load outbound runtime statistics: %w", err)
	}
	r.sqlite = sqliteStore
	r.nodes = plainstore.NewNodeStore(sqliteStore.DB())
	r.observer = observer
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
	observer := r.observer
	r.sqlite = nil
	r.nodes = nil
	r.mu.Unlock()

	err := r.proxies.Close()
	if observer != nil {
		err = errors.Join(err, observer.close())
	}
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
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	if err := nodes.ReplaceRemote(ctx, group, points, 0); err != nil {
		return err
	}
	configured, err := nodes.List(ctx)
	if err != nil {
		return err
	}
	for _, node := range configured {
		if node.Origin == "remote" && node.Group == group {
			r.proxies.Delete(node.ID)
		}
	}
	if r.observer != nil {
		existing := make(map[string]bool, len(configured))
		for _, node := range configured {
			existing[node.ID] = true
		}
		if err := r.observer.prune(ctx, existing); err != nil {
			return err
		}
	}
	return r.clearIdleProxies(ctx, nodes)
}

func (r *NodeRuntime) Remove(ctx context.Context, id string) error {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	deleteNode := func() error {
		err := nodes.Delete(ctx, id)
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil
		}
		return err
	}
	if r.observer != nil {
		if err := r.observer.delete(ctx, id, deleteNode); err != nil {
			return err
		}
	} else if err := deleteNode(); err != nil {
		return err
	}
	r.proxies.Delete(id)
	return r.clearIdleProxies(ctx, nodes)
}

func (r *NodeRuntime) Use(ctx context.Context, id string) error {
	return r.Select(ctx, contractnode.SelectionRequest{TCPID: id, UDPID: id})
}

func (r *NodeRuntime) Select(ctx context.Context, selection contractnode.SelectionRequest) error {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return err
	}
	if err := nodes.Select(ctx, selection); err != nil {
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
	return nodes.Selection(ctx)
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
	slices.SortFunc(items, func(a, b contractnode.Node) int { return cmp.Compare(a.ID, b.ID) })
	return items, nil
}

func (r *NodeRuntime) ExtraInfo(_ context.Context, id string) (contractnode.NodeExtraInfo, error) {
	if id == "" {
		return contractnode.NodeExtraInfo{}, errors.New("node id is empty")
	}

	var (
		info  contractnode.NodeExtraInfo
		found bool
	)
	r.proxies.Range(func(key string, entry *ProxyEntry) bool {
		if key != id || entry == nil {
			return true
		}
		entry.mu.RLock()
		proxy := entry.Proxy
		entry.mu.RUnlock()
		provider, ok := proxy.(interface {
			NodeExtraInfo() contractnode.NodeExtraInfo
		})
		if ok {
			candidate := provider.NodeExtraInfo()
			if candidate.GlobalProtect != nil || candidate.OpenVPN != nil {
				info = candidate
				found = true
			}
		}
		return false
	})
	if !found {
		return contractnode.NodeExtraInfo{}, plainstore.ErrNotFound
	}
	return info, nil
}

func (r *NodeRuntime) CloseNode(_ context.Context, id string) error {
	if id != "" {
		r.proxies.Delete(id)
	}
	return nil
}

func (r *NodeRuntime) Latency(ctx context.Context, id string, req contractnode.LatencyRequest) (contractnode.LatencyResponse, error) {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return contractnode.LatencyResponse{}, err
	}
	node, err := nodes.Get(ctx, id)
	if errors.Is(err, plainstore.ErrNotFound) {
		return contractnode.LatencyResponse{}, fmt.Errorf("node not found")
	}
	if err != nil {
		return contractnode.LatencyResponse{}, err
	}

	var latencyOptions latency.LatencyOptions
	switch req.Type {
	case "", "http", "tcp":
		if node.Latency != nil && strings.TrimSpace(node.Latency.URL) != "" {
			req.URL = strings.TrimSpace(node.Latency.URL)
			if latencyURL, err := url.Parse(req.URL); err == nil {
				latencyURL.Scheme = strings.ToLower(latencyURL.Scheme)
				req.URL = latencyURL.String()
			}
			latencyOptions.InsecureSkipVerify = node.Latency.InsecureSkipVerify
		}
	}

	proxy, err := r.getContractDialer(ctx, id, node)
	if err != nil {
		if r.observer != nil {
			r.observer.counter(id).probe(req.Type, contractnode.LatencyResponse{}, err)
		}
		return contractnode.LatencyResponse{}, err
	}
	result, err := latency.LatencyWithOptions(req, &latencyDialer{Proxy: proxy, ipv6: req.IPv6}, latencyOptions)
	if r.observer != nil {
		r.observer.counter(id).probe(req.Type, result, err)
	}
	return result, err
}

func (r *NodeRuntime) getContractDialer(ctx context.Context, id string, node contractnode.Node) (netapi.Proxy, error) {
	if id == "" {
		return nil, fmt.Errorf("node ID is empty")
	}
	if !node.Enabled {
		return nil, fmt.Errorf("node %q is disabled", node.Name)
	}
	switch node.IPVersion {
	case "", contractnode.IPVersionAuto, contractnode.IPVersionIPv4, contractnode.IPVersionIPv6:
	default:
		return nil, fmt.Errorf("unsupported node IP version %q", node.IPVersion)
	}
	r.credentialMu.Lock()
	defer r.credentialMu.Unlock()
	resolved, version, err := r.resolveCredentials(ctx, node)
	if err != nil {
		r.proxies.Delete(id)
		return nil, err
	}
	if r.credentialVersions == nil {
		r.credentialVersions = make(map[string]string)
	}
	if previous, ok := r.credentialVersions[id]; ok && previous != version {
		r.proxies.Delete(id)
	}
	r.credentialVersions[id] = version
	proxy, err := r.proxies.LoadOrCreate(ctx, id, func() (*ProxyEntry, error) {
		proxy, err := register.ContractDialer(resolved)
		if err != nil {
			return nil, err
		}
		return &ProxyEntry{Proxy: proxy, ContractConfig: &node, Name: node.Name}, nil
	})
	if err != nil {
		if r.observer != nil {
			r.observer.counter(id).failure(err)
		}
		return nil, err
	}
	if node.IPVersion == contractnode.IPVersionIPv4 || node.IPVersion == contractnode.IPVersionIPv6 {
		proxy = &singleFamilyNodeProxy{Proxy: proxy, ipVersion: node.IPVersion}
	}
	if r.observer != nil {
		proxy = &observedProxy{Proxy: proxy, c: r.observer.counter(id)}
	}
	return proxy, nil
}

func (r *NodeRuntime) GetTarget(ctx context.Context, network, mode string, target contractroute.Target) (netapi.Proxy, error) {
	if mode == "direct" {
		return direct.Default, nil
	}
	if mode == "block" {
		metrics.Counter.AddBlockConnection(mode)
		return reject.Default, nil
	}
	switch target.Type {
	case "", "default":
		return r.selected(ctx, network)
	case "node":
		return r.GetDialerByID(ctx, target.ID)
	case "selector":
		nodes, err := r.openNodes(ctx)
		if err != nil {
			return nil, err
		}
		selector, err := nodes.Selector(ctx, target.ID)
		if err != nil {
			return nil, err
		}
		netapi.GetContext(ctx).SetSelector(selector.ID, selector.Name)
		return r.GetDialerByID(ctx, selector.NodeID)
	default:
		return nil, fmt.Errorf("unknown destination type %q", target.Type)
	}
}

func (r *NodeRuntime) selected(ctx context.Context, network string) (netapi.Proxy, error) {
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
			return r.getContractDialer(ctx, selected.ID, selected)
		}
	case "udp":
		selected, ok, err := nodes.Selected(ctx, false)
		if err == nil && ok {
			return r.getContractDialer(ctx, selected.ID, selected)
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
	return r.getContractDialer(ctx, id, node)
}

type latencyDialer struct {
	netapi.Proxy
	ipv6 bool
}

func (d *latencyDialer) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	if d.IPVersion() == contractnode.IPVersionAuto {
		ctx = withResolverMode(ctx, d.ipv6)
	}
	return d.Proxy.Conn(ctx, address)
}

func (d *latencyDialer) PacketConn(ctx context.Context, address netapi.Address) (net.PacketConn, error) {
	if d.IPVersion() == contractnode.IPVersionAuto {
		ctx = withResolverMode(ctx, d.ipv6)
	}
	return d.Proxy.PacketConn(ctx, address)
}

func (d *latencyDialer) IPVersion() contractnode.IPVersion {
	proxy, ok := d.Proxy.(interface{ IPVersion() contractnode.IPVersion })
	if !ok {
		return contractnode.IPVersionAuto
	}
	return proxy.IPVersion()
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
