package subscr

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

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:generate protoc --go_out=. --go-grpc_out=. --go-grpc_opt=paths=source_relative --go_opt=paths=source_relative node.proto

var _ NodeManagerServer = (*NodeManager)(nil)
var _ proxy.Proxy = (*NodeManager)(nil)

type NodeManager struct {
	UnimplementedNodeManagerServer
	node       *Node
	configPath string
	lock       sync.RWMutex
	filelock   sync.RWMutex
	proxy.Proxy

	manager *manager
}

func NewNodeManager(configPath string) (n *NodeManager, err error) {
	n = &NodeManager{configPath: configPath}
	err = n.load()
	if err != nil {
		return n, fmt.Errorf("load config failed: %v", err)
	}

	n.manager = &manager{Manager: n.node.Manager}

	now, _ := n.Now(context.TODO(), &emptypb.Empty{})
	p, err := now.Conn()
	if err != nil {
		p = &proxy.DefaultProxy{}
	}

	n.Proxy = p
	return n, nil
}

func (n *NodeManager) Now(context.Context, *emptypb.Empty) (*Point, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	if n.node.NowNode == nil {
		return n.node.NowNode, nil
	}

	p, ok := n.manager.GetNodeByName(n.node.NowNode.Group, n.node.NowNode.Name)
	if !ok {
		return n.node.NowNode, nil
	}

	return p, nil
}

func (n *NodeManager) GetNode(_ context.Context, s *wrapperspb.StringValue) (*Point, error) {
	p, ok := n.manager.GetNode(s.Value)
	if !ok {
		return &Point{}, fmt.Errorf("node not found")
	}

	return p, nil
}

func (n *NodeManager) SaveNode(c context.Context, p *Point) (*Point, error) {
	_, err := n.DeleteNode(c, &wrapperspb.StringValue{Value: p.Hash})
	if err != nil {
		return &Point{}, fmt.Errorf("delete node failed: %v", err)
	}

	refreshHash(p)
	n.manager.AddNode(p)
	return p, n.save()
}

func refreshHash(p *Point) {
	p.Hash = ""
	z := sha256.Sum256([]byte(p.String()))
	p.Hash = hex.EncodeToString(z[:])
}

func (n *NodeManager) GetNodes(context.Context, *wrapperspb.StringValue) (*Node, error) {
	return n.node, nil
}

func (n *NodeManager) AddLink(_ context.Context, l *NodeLink) (*emptypb.Empty, error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.node.Links[l.Name] = l
	return &emptypb.Empty{}, n.save()
}

func (n *NodeManager) DeleteLink(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	delete(n.node.Links, s.Value)
	return &emptypb.Empty{}, n.save()
}

func (n *NodeManager) ChangeNowNode(c context.Context, s *wrapperspb.StringValue) (*Point, error) {
	p, err := n.GetNode(c, s)
	if err != nil {
		return &Point{}, fmt.Errorf("get node failed: %v", err)
	}

	n.lock.Lock()
	defer n.lock.Unlock()

	if n.node.NowNode.Hash == p.Hash {
		return p, nil
	}
	n.node.NowNode = p

	err = n.save()
	if err != nil {
		return p, fmt.Errorf("save config failed: %v", err)
	}

	proxy, err := p.Conn()
	if err != nil {
		return nil, fmt.Errorf("create conn failed: %w", err)
	}
	n.Proxy = proxy
	return n.node.NowNode, nil
}

func (n *NodeManager) RefreshSubscr(c context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	if n.node.Links == nil {
		n.node.Links = make(map[string]*NodeLink)
	}

	client := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{Timeout: time.Second * 30}).DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				return n.Conn(addr)
			},
		},
	}

	wg := sync.WaitGroup{}
	for _, l := range n.node.Links {
		wg.Add(1)
		go func(l *NodeLink) {
			defer wg.Done()
			if err := n.oneLinkGet(c, client, l); err != nil {
				log.Printf("get one link failed: %v", err)
			}
		}(l)
	}

	wg.Wait()

	err := n.save()
	return &emptypb.Empty{}, err
}

func (n *NodeManager) oneLinkGet(c context.Context, client *http.Client, link *NodeLink) error {
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
	dst, err := DecodeBytesBase64(body)
	if err != nil {
		return fmt.Errorf("decode body failed: %v", err)
	}
	n.manager.DeleteRemoteNodes(link.Name)
	for _, x := range bytes.Split(dst, []byte("\n")) {
		node, err := parseUrl(x, link.Name)
		if err != nil {
			log.Printf("parse url %s failed: %v\n", x, err)
			continue
		}
		_, err = n.SaveNode(c, node)
		if err != nil {
			log.Printf("save node %s failed: %v\n", x, err)
		}
	}

	return nil
}

func parseUrl(str []byte, group string) (node *Point, err error) {
	switch {
	// Shadowsocks
	case bytes.HasPrefix(str, []byte("ss://")):
		node, err = DefaultShadowsocks.ParseLink(str)
	// ShadowsocksR
	case bytes.HasPrefix(str, []byte("ssr://")):
		node, err = DefaultShadowsocksr.ParseLink(str)
	case bytes.HasPrefix(str, []byte("vmess://")):
		node, err = DefaultVmess.ParseLink(str)
	case bytes.HasPrefix(str, []byte("trojan://")):
		node, err = DefaultTrojan.ParseLink(str)
	default:
		err = fmt.Errorf("no support %s", string(str))
	}

	if err != nil {
		return nil, err
	}
	refreshHash(node)
	node.Group = group
	return node, err
}

func (n *NodeManager) DeleteNode(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	n.manager.DeleteNode(s.Value)
	return &emptypb.Empty{}, n.save()
}

func (n *NodeManager) Latency(c context.Context, s *wrapperspb.StringValue) (*wrapperspb.StringValue, error) {
	p, err := n.GetNode(c, s)
	if err != nil {
		return &wrapperspb.StringValue{}, fmt.Errorf("get node failed: %v", err)
	}

	px, err := p.Conn()
	if err != nil {
		logasfmt.Printf("get latency conn failed: %v\n", err)
		return &wrapperspb.StringValue{}, fmt.Errorf("get conn failed: %v", err)
	}

	t, err := latency.TcpLatency(
		func(_ context.Context, _, addr string) (net.Conn, error) { return px.Conn(addr) },
		"https://www.google.com/generate_204",
	)
	if err != nil {
		logasfmt.Printf("test latency failed: %v\n", err)
		return &wrapperspb.StringValue{Value: err.Error()}, err
	}
	return &wrapperspb.StringValue{Value: t.String()}, err
}

func (n *NodeManager) load() error {
	n.node = &Node{
		NowNode: &Point{},
		Links:   make(map[string]*NodeLink),
		Manager: &Manager{
			Groups:        make([]string, 0),
			GroupNodesMap: make(map[string]*ManagerNodeArray),
			Nodes:         make(map[string]*Point),
		},
	}
	_, err := os.Stat(n.configPath)
	if errors.Is(err, os.ErrNotExist) {
		return n.save()
	}

	n.filelock.RLock()
	defer n.filelock.RUnlock()
	data, err := ioutil.ReadFile(n.configPath)
	if err != nil {
		return fmt.Errorf("read node file failed: %v", err)
	}
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, n.node)

	if n.node.NowNode == nil {
		n.node.NowNode = &Point{}
	}
	if n.node.Links == nil {
		n.node.Links = make(map[string]*NodeLink)
	}

	if n.node.Manager == nil {
		n.node.Manager = &Manager{}
	}

	if n.node.Manager.Groups == nil {
		n.node.Manager.Groups = make([]string, 0)
		n.node.Manager.GroupNodesMap = make(map[string]*ManagerNodeArray)
		n.node.Manager.Nodes = make(map[string]*Point)
	}

	return err
}

func (n *NodeManager) save() error {
	_, err := os.Stat(path.Dir(n.configPath))
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(n.configPath), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make config dir failed: %w", err)
		}
	}

	n.filelock.Lock()
	defer n.filelock.Unlock()

	file, err := os.OpenFile(n.configPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("open node config failed: %v", err)
	}
	defer file.Close()
	data, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(n.node)
	if err != nil {
		return fmt.Errorf("marshal file failed: %v", err)
	}

	_, err = file.Write(data)
	return err
}
