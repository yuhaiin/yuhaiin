package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var _ proxy.Proxy = (*Nodes)(nil)

type Nodes struct {
	grpcnode.UnimplementedNodeManagerServer

	savaPath string
	lock     sync.RWMutex

	*outbound
	manager *manager
	link    *link
}

func NewNodes(configPath string) (n *Nodes) {
	n = &Nodes{savaPath: configPath}
	n.load()
	return
}

func (n *Nodes) Now(_ context.Context, r *node.NowReq) (*node.Point, error) {
	return n.outbound.Point(r.Net == node.NowReq_udp), nil
}

func (n *Nodes) GetNode(_ context.Context, s *wrapperspb.StringValue) (*node.Point, error) {
	p, ok := n.manager.GetNode(s.Value)
	if !ok {
		return &node.Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *Nodes) SaveNode(c context.Context, p *node.Point) (*node.Point, error) {
	n.manager.DeleteNode(p.Hash)
	refreshHash(p)
	n.manager.AddNode(p)
	return p, n.save()
}

func refreshHash(p *node.Point) {
	p.Hash = ""
	z := sha256.Sum256([]byte(p.String()))
	p.Hash = hex.EncodeToString(z[:])
}

func (n *Nodes) GetManager(context.Context, *wrapperspb.StringValue) (*node.Manager, error) {
	return n.manager.GetManager(), nil
}

func (n *Nodes) SaveLinks(_ context.Context, l *node.SaveLinkReq) (*emptypb.Empty, error) {
	n.link.Save(l.GetLinks())
	return &emptypb.Empty{}, n.save()
}

func (n *Nodes) DeleteLinks(_ context.Context, s *node.LinkReq) (*emptypb.Empty, error) {
	n.link.Delete(s.GetNames())
	return &emptypb.Empty{}, n.save()
}

func (n *Nodes) Use(c context.Context, s *node.UseReq) (*node.Point, error) {
	p, err := n.GetNode(c, &wrapperspb.StringValue{Value: s.Hash})
	if err != nil {
		return &node.Point{}, fmt.Errorf("get node failed: %v", err)
	}

	if s.Tcp {
		n.outbound.Save(p, false)
	}
	if s.Udp {
		n.outbound.Save(p, true)
	}

	err = n.save()
	if err != nil {
		return p, fmt.Errorf("save config failed: %v", err)
	}
	return p, nil
}

func (n *Nodes) GetLinks(ctx context.Context, in *emptypb.Empty) (*node.GetLinksResp, error) {
	return &node.GetLinksResp{Links: n.link.Links()}, nil
}

func (n *Nodes) UpdateLinks(c context.Context, req *node.LinkReq) (*emptypb.Empty, error) {
	n.link.Update(req.Names)
	return &emptypb.Empty{}, n.save()
}

func (n *Nodes) DeleteNode(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.manager.DeleteNode(s.Value)
	return &emptypb.Empty{}, n.save()
}

func (n *Nodes) Latency(c context.Context, req *node.LatencyReq) (*node.LatencyResp, error) {
	resp := &node.LatencyResp{HashLatencyMap: make(map[string]*node.LatencyRespLatency)}
	var respLock sync.Mutex

	var wg sync.WaitGroup
	for _, s := range req.Requests {
		wg.Add(1)
		go func(s *node.LatencyReqRequest) {
			defer wg.Done()
			p, err := n.GetNode(c, &wrapperspb.StringValue{Value: s.GetHash()})
			if err != nil {
				return
			}

			px, err := register.Dialer(p)
			if err != nil {
				return
			}

			var tcp, udp string
			if s.Tcp {
				t, err := latency.HTTP(px, "https://clients3.google.com/generate_204")
				if err == nil {
					tcp = t.String()
				}
			}

			if s.Udp {
				t, err := latency.DNS(px, "1.1.1.1:53", "www.google.com")
				if err == nil {
					udp = t.String()
				}
			}

			respLock.Lock()
			resp.HashLatencyMap[s.Hash] = &node.LatencyRespLatency{Tcp: tcp, Udp: udp}
			respLock.Unlock()
		}(s)
	}

	wg.Wait()
	return resp, nil
}

func (n *Nodes) load() {
	no := &node.Node{}

	n.lock.RLock()
	defer n.lock.RUnlock()

	if data, err := os.ReadFile(n.savaPath); err == nil {
		if err = (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, no); err != nil {
			log.Printf("unmarshal node file failed: %v\n", err)
		}
	} else {
		log.Printf("read node file failed: %v\n", err)
	}

_init:
	for {
		switch {
		case no.Tcp == nil:
			no.Tcp = &node.Point{}
		case no.Udp == nil:
			no.Udp = &node.Point{}
		case no.Links == nil:
			no.Links = make(map[string]*node.NodeLink)
		case no.Manager == nil:
			no.Manager = &node.Manager{}
		case no.Manager.Groups == nil:
			no.Manager.Groups = make([]string, 0)
			no.Manager.GroupNodesMap = make(map[string]*node.ManagerNodeArray)
			no.Manager.Nodes = make(map[string]*node.Point)
		default:
			break _init
		}
	}

	n.manager = NewManager(no.Manager)
	n.outbound = NewOutbound(no.Tcp, no.Udp, n.manager)
	n.link = NewLink(n.outbound, n.manager, no.Links)
}

func (n *Nodes) save() error {
	_, err := os.Stat(path.Dir(n.savaPath))
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(n.savaPath), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make config dir failed: %w", err)
		}
	}

	n.lock.Lock()
	defer n.lock.Unlock()

	data, err := protojson.MarshalOptions{Indent: "\t"}.
		Marshal(
			&node.Node{
				Tcp:     n.outbound.Point(false),
				Udp:     n.outbound.Point(true),
				Links:   n.link.Links(),
				Manager: n.manager.GetManager(),
			})
	if err != nil {
		return fmt.Errorf("marshal file failed: %v", err)
	}

	return os.WriteFile(n.savaPath, data, os.ModePerm)
}
