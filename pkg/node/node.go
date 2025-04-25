package node

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/latency"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Nodes struct {
	gn.UnimplementedNodeServer
	manager *Manager
}

func (n *Nodes) Now(context.Context, *emptypb.Empty) (*gn.NowResp, error) {
	return gn.NowResp_builder{
		Tcp: n.manager.GetNow(true),
		Udp: n.manager.GetNow(false),
	}.Build(), nil
}

func (n *Nodes) Get(_ context.Context, s *wrapperspb.StringValue) (*point.Point, error) {
	p, ok := n.manager.GetNode(s.Value)
	if !ok {
		return &point.Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *Nodes) Save(c context.Context, p *point.Point) (*point.Point, error) {
	if p.GetName() == "" || p.GetGroup() == "" {
		return &point.Point{}, fmt.Errorf("point name or group is empty")
	}
	p.SetOrigin(point.Origin_manual)
	n.manager.SaveNode(p)
	return p, n.manager.Save()
}

func (n *Nodes) List(ctx context.Context, _ *emptypb.Empty) (*gn.NodesResponse, error) {
	return gn.NodesResponse_builder{
		Groups: n.manager.GetGroups(),
	}.Build(), nil
}

func (n *Nodes) Use(c context.Context, s *gn.UseReq) (*point.Point, error) {
	err := n.manager.UsePoint(s.GetTcp(), s.GetUdp(), s.GetHash())
	if err != nil {
		return nil, fmt.Errorf("use point failed: %w", err)
	}

	err = n.manager.Save()
	if err != nil {
		return nil, fmt.Errorf("save config failed: %w", err)
	}

	return &point.Point{}, nil
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
		netctx.Resolver.Mode = netapi.ResolverModePreferIPv6
	} else {
		netctx.Resolver.Mode = netapi.ResolverModePreferIPv4
	}
	return w.Proxy.Conn(netctx, a)
}

func (w *latencyDialer) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	netctx := netapi.GetContext(ctx)
	if w.ipv6 {
		netctx.Resolver.Mode = netapi.ResolverModePreferIPv6
	} else {
		netctx.Resolver.Mode = netapi.ResolverModePreferIPv4
	}
	return w.Proxy.PacketConn(netctx, a)
}

func (n *Nodes) Latency(c context.Context, req *latency.Requests) (*latency.Response, error) {
	resp := &latency.Response_builder{
		IdLatencyMap: make(map[string]*latency.Reply),
	}
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, s := range req.GetRequests() {
		wg.Add(1)
		go func(s *latency.Request) {
			defer wg.Done()
			px, err := n.manager.Outbound().GetDialerByID(c, s.GetHash())
			if err != nil {
				return
			}

			px = &latencyDialer{Proxy: px, ipv6: s.GetIpv6()}

			t, err := s.GetProtocol().Latency(px)

			mu.Lock()
			if err != nil {
				log.Error("latency failed", "err", err)
				resp.IdLatencyMap[s.GetId()] = (&latency.Reply_builder{
					Error: (&latency.Error_builder{Msg: proto.String(err.Error())}).Build(),
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

func (n *Nodes) Activates(context.Context, *emptypb.Empty) (*gn.ActivatesResponse, error) {
	nodes := []*point.Point{}
	for _, v := range n.manager.store.Range {
		nodes = append(nodes, v.Config)
	}

	return gn.ActivatesResponse_builder{
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
		Tcp:   &point.Point{},
		Udp:   &point.Point{},
		Links: map[string]*subscribe.Link{},
		Manager: (&node.Manager_builder{
			GroupsV2: map[string]*node.Nodes{},
			Nodes:    map[string]*point.Point{},
			Tags:     map[string]*pt.Tags{},
		}).Build(),
	}

	defaultNode.Tcp.SetHash("inittcp")
	defaultNode.Udp.SetHash("initudp")

	return jsondb.Open(path, defaultNode.Build())
}
