package node

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Nodes struct {
	api.UnimplementedNodeServer
	manager *Manager
}

func (n *Nodes) Now(context.Context, *emptypb.Empty) (*api.NowResp, error) {
	return api.NowResp_builder{
		Tcp: n.manager.GetNow(true),
		Udp: n.manager.GetNow(false),
	}.Build(), nil
}

func (n *Nodes) Get(_ context.Context, s *wrapperspb.StringValue) (*node.Point, error) {
	p, ok := n.manager.GetNode(s.Value)
	if !ok {
		return &node.Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *Nodes) Save(c context.Context, p *node.Point) (*node.Point, error) {
	if p.GetName() == "" || p.GetGroup() == "" {
		return &node.Point{}, fmt.Errorf("point name or group is empty")
	}
	p.SetOrigin(node.Origin_manual)
	n.manager.SaveNode(p)
	return p, n.manager.Save()
}

func (n *Nodes) List(ctx context.Context, _ *emptypb.Empty) (*api.NodesResponse, error) {
	resp := api.NodesResponse_builder{}

	for g, v := range n.manager.GetGroups() {
		slices.SortFunc(v, func(a, b *api.NodesResponse_Node) int { return cmp.Compare(a.GetName(), b.GetName()) })
		g := api.NodesResponse_Group_builder{
			Name:  proto.String(g),
			Nodes: v,
		}.Build()

		resp.Groups = append(resp.Groups, g)
	}

	slices.SortFunc(resp.Groups, func(a, b *api.NodesResponse_Group) int {
		return cmp.Compare(a.GetName(), b.GetName())
	})

	return resp.Build(), nil
}

func (n *Nodes) Use(c context.Context, s *api.UseReq) (*node.Point, error) {
	err := n.manager.UsePoint(s.GetHash())
	if err != nil {
		return nil, fmt.Errorf("use point failed: %w", err)
	}

	err = n.manager.Save()
	if err != nil {
		return nil, fmt.Errorf("save config failed: %w", err)
	}

	return &node.Point{}, nil
}

func (n *Nodes) Remove(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.manager.DeleteNode(s.Value)
	return &emptypb.Empty{}, n.manager.Save()
}

type latencyDialer struct {
	netapi.Proxy
	ipv6 bool
}

func (w *latencyDialer) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	netctx := netapi.GetContext(ctx)
	if w.ipv6 {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv6)
	} else {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
	}
	return w.Proxy.Conn(netctx, a)
}

func (w *latencyDialer) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	netctx := netapi.GetContext(ctx)
	if w.ipv6 {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv6)
	} else {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
	}
	return w.Proxy.PacketConn(netctx, a)
}

func (n *Nodes) Latency(c context.Context, req *node.Requests) (*node.Response, error) {
	resp := &node.Response_builder{
		IdLatencyMap: make(map[string]*node.Reply),
	}
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, s := range req.GetRequests() {
		wg.Add(1)
		go func(s *node.Request) {
			defer wg.Done()
			px, err := n.manager.Outbound().GetDialerByID(c, s.GetHash())
			if err != nil {
				return
			}

			px = &latencyDialer{Proxy: px, ipv6: s.GetIpv6()}

			t, err := latency.Latency(s.GetMethod(), px)

			mu.Lock()
			if err != nil {
				log.Error("latency failed", "err", err)
				resp.IdLatencyMap[s.GetId()] = (&node.Reply_builder{
					Error: (&node.Error_builder{Msg: proto.String(err.Error())}).Build(),
				}).Build()
			} else {
				resp.IdLatencyMap[s.GetId()] = t
			}
			mu.Unlock()
		}(s)
	}

	wg.Wait()

	return resp.Build(), nil
}

func (n *Nodes) Activates(context.Context, *emptypb.Empty) (*api.ActivatesResponse, error) {
	nodes := []*node.Point{}
	for _, v := range n.manager.store.Range {
		nodes = append(nodes, v.Config)
	}

	return api.ActivatesResponse_builder{
		Nodes: nodes,
	}.Build(), nil
}

func (n *Nodes) Close(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	if req.GetValue() == "" {
		return &emptypb.Empty{}, nil
	}

	n.manager.store.Delete(req.GetValue())

	return &emptypb.Empty{}, nil
}

func load(path string) *jsondb.DB[*node.Node] {
	defaultNode := &node.Node_builder{
		Tcp:   &node.Point{},
		Udp:   &node.Point{},
		Links: map[string]*node.Link{},
		Manager: (&node.Manager_builder{
			Nodes: map[string]*node.Point{},
			Tags:  map[string]*node.Tags{},
		}).Build(),
	}

	defaultNode.Tcp.SetHash("inittcp")
	defaultNode.Udp.SetHash("initudp")

	return jsondb.Open(path, defaultNode.Build())
}
