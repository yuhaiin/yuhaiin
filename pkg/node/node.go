package node

import (
	"context"
	"fmt"
	"iter"
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
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Nodes struct {
	gn.UnimplementedNodeServer

	ruleTags func() iter.Seq[string]

	db       *jsondb.DB[*node.Node]
	manager  *manager
	outBound *outbound
	links    *link
}

func NewNodes(path string) *Nodes {
	f := &Nodes{
		db: load(path),
	}

	f.manager = NewManager(f.db.Data.Manager)
	f.outBound = NewOutbound(f.db, f.manager)
	f.links = NewLink(f.db, f.outBound, f.manager)

	return f
}

func (n *Nodes) SetRuleTags(f func() iter.Seq[string]) { n.ruleTags = f }

func (n *Nodes) Now(context.Context, *emptypb.Empty) (*gn.NowResp, error) {
	return &gn.NowResp{
		Tcp: n.db.Data.Tcp,
		Udp: n.db.Data.Udp,
	}, nil
}

func (n *Nodes) Get(_ context.Context, s *wrapperspb.StringValue) (*point.Point, error) {
	p, ok := n.manager.GetNode(s.Value)
	if !ok {
		return &point.Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *Nodes) Save(c context.Context, p *point.Point) (*point.Point, error) {
	if p.Name == "" || p.Group == "" {
		return &point.Point{}, fmt.Errorf("add point name or group is empty")
	}
	n.manager.DeleteNode(p.Hash)
	n.manager.AddNode(p)
	return p, n.db.Save()
}

func (n *Nodes) List(ctx context.Context, _ *emptypb.Empty) (*gn.NodesResponse, error) {
	return &gn.NodesResponse{
		Groups: n.manager.GetGroupsV2(),
	}, nil
}

func (n *Nodes) Use(c context.Context, s *gn.UseReq) (*point.Point, error) {
	p, err := n.Get(c, &wrapperspb.StringValue{Value: s.Hash})
	if err != nil {
		return &point.Point{}, fmt.Errorf("get node failed: %w", err)
	}

	if s.Tcp {
		n.db.Data.Tcp = p
	}
	if s.Udp {
		n.db.Data.Udp = p
	}

	err = n.db.Save()
	if err != nil {
		return p, fmt.Errorf("save config failed: %w", err)
	}
	return p, nil
}

func (n *Nodes) Remove(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.manager.DeleteNode(s.Value)
	return &emptypb.Empty{}, n.db.Save()
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
	resp := &latency.Response{IdLatencyMap: make(map[string]*latency.Reply)}
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, s := range req.Requests {
		wg.Add(1)
		go func(s *latency.Request) {
			defer wg.Done()
			p, err := n.Get(c, &wrapperspb.StringValue{Value: s.GetHash()})
			if err != nil {
				return
			}

			px, err := n.outBound.GetDialer(p)
			if err != nil {
				return
			}

			px = &latencyDialer{Proxy: px, ipv6: s.GetIpv6()}

			z, ok := s.Protocol.Protocol.(latency.Latencier)
			if !ok {
				return
			}

			t, err := z.Latency(px)
			if err != nil {
				log.Error("latency failed", "err", err)
				return
			}

			mu.Lock()
			resp.IdLatencyMap[s.Id] = t
			mu.Unlock()
		}(s)
	}

	wg.Wait()
	return resp, nil
}

func (n *Nodes) Outbound() *outbound { return n.outBound }

func load(path string) *jsondb.DB[*node.Node] {
	defaultNode := &node.Node{
		Tcp:   &point.Point{},
		Udp:   &point.Point{},
		Links: map[string]*subscribe.Link{},
		Manager: &node.Manager{
			GroupsV2: map[string]*node.Nodes{},
			Nodes:    map[string]*point.Point{},
			Tags:     map[string]*pt.Tags{},
		},
	}

	return jsondb.Open(path, defaultNode)
}
