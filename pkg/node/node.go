package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node/parser"
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

	savaPath       string
	lock, filelock sync.RWMutex

	tcpProxy, udpProxy proxy.Proxy
	tcp, udp           *node.Point

	manager *manager
	links   map[string]*node.NodeLink
}

func NewNodes(configPath string) (n *Nodes) {
	n = &Nodes{savaPath: configPath}
	n.load()
	return
}

func (n *Nodes) tcpDialer() proxy.Proxy {
	if n.tcpProxy == nil {
		now, _ := n.Now(context.TODO(), &node.NowReq{Net: node.NowReq_tcp})
		p, err := register.Dialer(now)
		if err != nil {
			log.Printf("create conn failed: %v", err)
			return direct.Default
		}

		n.tcpProxy = p
	}

	return n.tcpProxy
}

func (n *Nodes) Conn(host proxy.Address) (net.Conn, error) {
	return n.tcpDialer().Conn(host)
}

func (n *Nodes) PacketConn(host proxy.Address) (net.PacketConn, error) {
	if n.udpProxy == nil {
		now, _ := n.Now(context.TODO(), &node.NowReq{Net: node.NowReq_udp})
		p, err := register.Dialer(now)
		if err != nil {
			log.Printf("create conn failed: %v", err)
			return direct.Default.PacketConn(host)
		}
		n.udpProxy = p
	}

	return n.udpProxy.PacketConn(host)
}

func (n *Nodes) Now(_ context.Context, r *node.NowReq) (*node.Point, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	var now *node.Point

	switch r.Net {
	case node.NowReq_tcp:
		now = n.tcp
	case node.NowReq_udp:
		now = n.udp
	}

	if now == nil {
		now = &node.Point{}
		return now, nil
	}

	p, ok := n.manager.GetNodeByName(now.Group, now.Name)
	if !ok {
		return now, nil
	}

	return p, nil
}

func (n *Nodes) GetNode(_ context.Context, s *wrapperspb.StringValue) (*node.Point, error) {
	p, ok := n.manager.GetNode(s.Value)
	if !ok {
		return &node.Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *Nodes) SaveNode(c context.Context, p *node.Point) (*node.Point, error) {
	n.saveNode(p)
	return p, n.save()
}

func (n *Nodes) saveNode(p *node.Point) *node.Point {
	n.manager.DeleteNode(p.Hash)
	refreshHash(p)
	n.manager.AddNode(p)
	return p
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
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.links == nil {
		n.links = make(map[string]*node.NodeLink)
	}
	for _, l := range l.Links {
		n.links[l.Name] = l
	}
	return &emptypb.Empty{}, n.save()
}

func (n *Nodes) DeleteLinks(_ context.Context, s *node.LinkReq) (*emptypb.Empty, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	for _, l := range s.Names {
		delete(n.links, l)
	}

	return &emptypb.Empty{}, n.save()
}

func (n *Nodes) Use(c context.Context, s *node.UseReq) (*node.Point, error) {
	p, err := n.GetNode(c, &wrapperspb.StringValue{Value: s.Hash})
	if err != nil {
		return &node.Point{}, fmt.Errorf("get node failed: %v", err)
	}

	n.lock.Lock()
	defer n.lock.Unlock()

	if s.Tcp && n.tcp.Hash != p.Hash {
		n.tcp = p
		n.tcpProxy = nil
	}
	if s.Udp && n.udp.Hash != p.Hash {
		n.udp = p
		n.udpProxy = nil
	}

	err = n.save()
	if err != nil {
		return p, fmt.Errorf("save config failed: %v", err)
	}
	return p, nil
}

func (n *Nodes) GetLinks(ctx context.Context, in *emptypb.Empty) (*node.GetLinksResp, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return &node.GetLinksResp{Links: n.links}, nil
}

func (n *Nodes) UpdateLinks(c context.Context, req *node.LinkReq) (*emptypb.Empty, error) {
	if n.links == nil {
		n.links = make(map[string]*node.NodeLink)
	}

	client := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Println("dial:", network, addr)
				ad, err := proxy.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %v", err)
				}

				ipHost, err := ad.IPHost()
				if err == nil {
					ctx, cancel := context.WithTimeout(ctx, time.Second*5)
					defer cancel()
					conn, err := dialer.DialContext(ctx, network, ipHost)
					if err == nil {
						return conn, nil
					}
				}

				return n.tcpDialer().Conn(ad)
			},
		},
	}

	wg := sync.WaitGroup{}
	for _, l := range req.Names {
		l, ok := n.links[l]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(l *node.NodeLink) {
			defer wg.Done()
			if err := n.oneLinkGet(c, client, l); err != nil {
				log.Printf("get one link failed: %v", err)
			}
		}(l)
	}

	wg.Wait()

	return &emptypb.Empty{}, n.save()
}

func (n *Nodes) oneLinkGet(c context.Context, client *http.Client, link *node.NodeLink) error {
	req, err := http.NewRequest("GET", link.Url, nil)
	if err != nil {
		return fmt.Errorf("create request failed: %v", err)
	}

	req.Header.Set("User-Agent", "yuhaiin")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("get %s failed: %v", link.Name, err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read body failed: %v", err)
	}
	dst, err := parser.DecodeBytesBase64(body)
	if err != nil {
		return fmt.Errorf("decode body failed: %v", err)
	}
	n.manager.DeleteRemoteNodes(link.Name)
	for _, x := range bytes.Split(dst, []byte("\n")) {
		node, err := parseUrl(x, link)
		if err != nil {
			log.Printf("parse url %s failed: %v\n", x, err)
			continue
		}
		n.saveNode(node)
	}

	return nil
}

func parseUrl(str []byte, l *node.NodeLink) (no *node.Point, err error) {
	t := l.Type

	if t == node.NodeLink_reserve {
		switch {
		case bytes.HasPrefix(str, []byte("ss://")):
			t = node.NodeLink_shadowsocks
		case bytes.HasPrefix(str, []byte("ssr://")):
			t = node.NodeLink_shadowsocksr
		case bytes.HasPrefix(str, []byte("vmess://")):
			t = node.NodeLink_vmess
		case bytes.HasPrefix(str, []byte("trojan://")):
			t = node.NodeLink_trojan
		}
	}
	no, err = parser.Parse(t, str)
	if err != nil {
		return nil, fmt.Errorf("parse link data failed: %v", err)
	}
	refreshHash(no)
	no.Group = l.Name
	return no, nil
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

	n.filelock.RLock()
	defer n.filelock.RUnlock()

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

	n.tcp, n.udp, n.links = no.Tcp, no.Udp, no.Links
	n.manager = &manager{Manager: no.Manager}
}

func (n *Nodes) save() error {
	_, err := os.Stat(path.Dir(n.savaPath))
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(n.savaPath), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make config dir failed: %w", err)
		}
	}

	n.filelock.Lock()
	defer n.filelock.Unlock()

	var manager *node.Manager
	if n.manager != nil {
		manager = n.manager.GetManager()
	}

	data, err := protojson.MarshalOptions{Indent: "\t"}.
		Marshal(&node.Node{Tcp: n.tcp, Udp: n.udp, Links: n.links, Manager: manager})
	if err != nil {
		return fmt.Errorf("marshal file failed: %v", err)
	}

	return os.WriteFile(n.savaPath, data, os.ModePerm)
}
