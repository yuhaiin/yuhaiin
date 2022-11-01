package node

import (
	"context"
	"fmt"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var _ proxy.Proxy = (*Nodes)(nil)

type Nodes struct {
	grpcnode.UnimplementedNodeServer

	fileStore *FileStore

	*outbound
	manager *manager
}

func NewNodes(fileStore *FileStore) *Nodes {
	return &Nodes{
		fileStore: fileStore,
		outbound:  fileStore.outbound(),
		manager:   fileStore.manager(),
	}
}

func (n *Nodes) Now(_ context.Context, r *grpcnode.NowReq) (*point.Point, error) {
	return n.outbound.Point(r.Net == grpcnode.NowReq_udp), nil
}

func (n *Nodes) Get(_ context.Context, s *wrapperspb.StringValue) (*point.Point, error) {
	p, ok := n.manager.GetNode(s.Value)
	if !ok {
		return &point.Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *Nodes) Save(c context.Context, p *point.Point) (*point.Point, error) {
	n.manager.DeleteNode(p.Hash)
	refreshHash(p)
	n.manager.AddNode(p)
	return p, n.fileStore.Save()
}

func (n *Nodes) Manager(context.Context, *wrapperspb.StringValue) (*node.Manager, error) {
	return n.manager.GetManager(), nil
}

func (n *Nodes) Use(c context.Context, s *grpcnode.UseReq) (*point.Point, error) {
	p, err := n.Get(c, &wrapperspb.StringValue{Value: s.Hash})
	if err != nil {
		return &point.Point{}, fmt.Errorf("get node failed: %v", err)
	}

	if s.Tcp {
		n.outbound.Save(p, false)
	}
	if s.Udp {
		n.outbound.Save(p, true)
	}

	err = n.fileStore.Save()
	if err != nil {
		return p, fmt.Errorf("save config failed: %v", err)
	}
	return p, nil
}

func (n *Nodes) Remove(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.manager.DeleteNode(s.Value)
	return &emptypb.Empty{}, n.fileStore.Save()
}

func (n *Nodes) Latency(c context.Context, req *grpcnode.LatencyReq) (*grpcnode.LatencyResp, error) {
	resp := &grpcnode.LatencyResp{HashLatencyMap: make(map[string]*grpcnode.LatencyRespLatency)}
	var respLock sync.Mutex

	var wg sync.WaitGroup
	for _, s := range req.Requests {
		wg.Add(1)
		go func(s *grpcnode.LatencyReqRequest) {
			defer wg.Done()
			p, err := n.Get(c, &wrapperspb.StringValue{Value: s.GetHash()})
			if err != nil {
				return
			}

			px, err := register.Dialer(p)
			if err != nil {
				return
			}

			times := &grpcnode.LatencyRespLatency{
				Times: make([]*durationpb.Duration, 0, len(s.Protocols)),
			}

			for _, r := range s.Protocols {
				var t *durationpb.Duration
				z, ok := r.Protocol.(interface {
					Latency(proxy.Proxy) (*durationpb.Duration, error)
				})
				if ok {
					t, err = z.Latency(px)
					if err != nil {
						log.Errorln("latency failed:", err)
					}
				}

				times.Times = append(times.Times, t)
			}

			respLock.Lock()
			resp.HashLatencyMap[s.Hash] = times
			respLock.Unlock()
		}(s)
	}

	wg.Wait()
	return resp, nil
}
