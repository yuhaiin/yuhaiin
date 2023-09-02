package node

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/latency"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var _ netapi.Proxy = (*Nodes)(nil)

type Nodes struct {
	gn.UnimplementedNodeServer
	netapi.EmptyDispatch

	fileStore *FileStore
}

func NewNodes(fileStore *FileStore) *Nodes { return &Nodes{fileStore: fileStore} }

func (n *Nodes) Now(_ context.Context, r *gn.NowReq) (*point.Point, error) {
	if r.Net == gn.NowReq_udp {
		return n.fileStore.db.Data.Udp, nil
	} else {
		return n.fileStore.db.Data.Tcp, nil
	}
}

func (n *Nodes) Get(_ context.Context, s *wrapperspb.StringValue) (*point.Point, error) {
	p, ok := n.manager().GetNode(s.Value)
	if !ok {
		return &point.Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *Nodes) Save(c context.Context, p *point.Point) (*point.Point, error) {
	n.manager().DeleteNode(p.Hash)
	n.manager().AddNode(p)
	return p, n.fileStore.Save()
}

func (n *Nodes) Manager(context.Context, *wrapperspb.StringValue) (*node.Manager, error) {
	return n.manager().GetManager(), nil
}

func (n *Nodes) Use(c context.Context, s *gn.UseReq) (*point.Point, error) {
	p, err := n.Get(c, &wrapperspb.StringValue{Value: s.Hash})
	if err != nil {
		return &point.Point{}, fmt.Errorf("get node failed: %w", err)
	}

	if s.Tcp {
		n.fileStore.db.Data.Tcp = p
	}
	if s.Udp {
		n.fileStore.db.Data.Udp = p
	}

	err = n.fileStore.Save()
	if err != nil {
		return p, fmt.Errorf("save config failed: %w", err)
	}
	return p, nil
}

func (n *Nodes) Remove(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.manager().DeleteNode(s.Value)
	return &emptypb.Empty{}, n.fileStore.Save()
}

func (n *Nodes) Latency(c context.Context, req *latency.Requests) (*latency.Response, error) {
	resp := &latency.Response{IdLatencyMap: make(map[string]*durationpb.Duration)}
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

			px, err := register.Dialer(p)
			if err != nil {
				return
			}

			var t *durationpb.Duration
			z, ok := s.Protocol.Protocol.(interface {
				Latency(netapi.Proxy) (*durationpb.Duration, error)
			})
			if ok {
				t, err = z.Latency(px)
				if err != nil {
					log.Error("latency failed", "err", err)
				}
			}

			mu.Lock()
			resp.IdLatencyMap[s.Id] = t
			mu.Unlock()
		}(s)
	}

	wg.Wait()
	return resp, nil
}

func (n *Nodes) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return n.fileStore.outbound().Conn(ctx, addr)
}
func (n *Nodes) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return n.fileStore.outbound().PacketConn(ctx, addr)
}
func (n *Nodes) manager() *manager { return n.fileStore.manager() }
