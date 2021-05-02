package subscr

import (
	"bytes"
	context "context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	sync "sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"google.golang.org/protobuf/encoding/protojson"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

var _ NodeManagerServer = (*NodeManager)(nil)

type NodeManager struct {
	UnimplementedNodeManagerServer
	node       *Node
	configPath string
	lock       sync.RWMutex
}

func NewNodeManager(configPath string) (n *NodeManager, err error) {
	n = &NodeManager{
		configPath: configPath,
	}
	n.node, err = n.decodeJSON()
	return
}

func (n *NodeManager) Now(context.Context, *emptypb.Empty) (*Point, error) {
	return n.node.NowNode, nil
}

func (n *NodeManager) GetNode(_ context.Context, s *wrapperspb.StringValue) (*Point, error) {
	p, ok := n.node.Nodes[s.Value]
	if ok {
		return p, nil
	}
	return nil, fmt.Errorf("can't find node %v", s.Value)
}

func (n *NodeManager) AddNode(c context.Context, p *Point) (*emptypb.Empty, error) {
	_, err := n.DeleteNode(c, &wrapperspb.StringValue{Value: p.NHash})
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("delete node failed: %v", err)
	}

	_, ok := n.node.GroupNodesMap[p.GetNGroup()]
	if !ok {
		n.node.Groups = append(n.node.Groups, p.NGroup)
		n.node.GroupNodesMap[p.NGroup] = &NodeNodeArray{
			Group:       p.NGroup,
			Nodes:       make([]string, 0),
			NodeHashMap: make(map[string]string),
		}
	}

	n.node.GroupNodesMap[p.NGroup].NodeHashMap[p.NName] = p.NHash
	n.node.GroupNodesMap[p.NGroup].Nodes = append(n.node.GroupNodesMap[p.NGroup].Nodes, p.NName)

	n.node.Nodes[p.NHash] = p

	return &emptypb.Empty{}, nil
}

func (n *NodeManager) GetNodes(context.Context, *wrapperspb.StringValue) (*Node, error) {
	return n.node, nil
}

func (n *NodeManager) AddLink(_ context.Context, l *NodeLink) (*emptypb.Empty, error) {
	n.node.Links[l.Name] = l
	return &emptypb.Empty{}, nil
}

func (n *NodeManager) DeleteLink(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	delete(n.node.Links, s.Value)
	return &emptypb.Empty{}, nil
}

func (n *NodeManager) ChangeNowNode(c context.Context, s *wrapperspb.StringValue) (*Point, error) {
	p, err := n.GetNode(c, s)
	if err != nil {
		return &Point{}, fmt.Errorf("get node failed: %v", err)
	}

	n.node.NowNode = p
	return n.node.NowNode, nil
}

func (n *NodeManager) RefreshSubscr(c context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {

	if n.node.Links == nil {
		n.node.Links = make(map[string]*NodeLink)
	}
	if n.node.Nodes == nil {
		n.node.Nodes = make(map[string]*Point)
	}
	for key := range n.node.Links {
		n.oneLinkGet(c, n.node.Links[key])
	}

	err := n.enCodeJSON(n.node)
	return &emptypb.Empty{}, err
}

func (n *NodeManager) oneLinkGet(c context.Context, link *NodeLink) {
	client := http.Client{Timeout: time.Second * 30}
	res, err := client.Get(link.Url)
	if err != nil {
		log.Println(err)
		return
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return
	}
	dst, err := DecodeBytesBase64(body)
	if err != nil {
		log.Println(err)
		return
	}
	n.deleteRemoteNodes(link.Name)
	for _, x := range bytes.Split(dst, []byte("\n")) {
		node, err := parseUrl(x, link.Name)
		if err != nil {
			log.Println(err)
			continue
		}
		n.AddNode(c, node)
	}
}

func (n *NodeManager) deleteRemoteNodes(group string) {
	x, ok := n.node.GroupNodesMap[group]
	if !ok {
		return
	}

	ns := x.Nodes
	msmap := x.NodeHashMap
	left := make([]string, 0)
	for i := range ns {
		if n.node.Nodes[msmap[ns[i]]].GetNOrigin() != Point_remote {
			left = append(left, ns[i])
			continue
		}

		delete(n.node.Nodes, msmap[ns[i]])
		delete(n.node.GroupNodesMap[group].NodeHashMap, ns[i])
	}

	if len(left) == 0 {
		delete(n.node.GroupNodesMap, group)
		return
	}

	n.node.GroupNodesMap[group].Nodes = left
}

var (
	ss  = &shadowsocks{}
	ssr = &shadowsocksr{}
	vm  = &vmess{}
)

func parseUrl(str []byte, group string) (node *Point, err error) {
	switch {
	// Shadowsocks
	case bytes.HasPrefix(str, []byte("ss://")):
		node, err := ss.ParseLink(str, group)
		if err != nil {
			return nil, err
		}
		return node, nil
	// ShadowsocksR
	case bytes.HasPrefix(str, []byte("ssr://")):
		node, err := ssr.ParseLink(str, group)
		if err != nil {
			return nil, err
		}
		return node, nil
	case bytes.HasPrefix(str, []byte("vmess://")):
		node, err := vm.ParseLink(str, group)
		if err != nil {
			return nil, err
		}
		return node, nil
	default:
		return nil, errors.New("no support " + string(str))
	}
}

func (n *NodeManager) DeleteNode(_ context.Context, s *wrapperspb.StringValue) (*emptypb.Empty, error) {
	p, ok := n.node.Nodes[s.Value]
	if !ok {
		return &emptypb.Empty{}, nil
	}

	delete(n.node.GroupNodesMap[p.NGroup].NodeHashMap, p.NName)

	for i, x := range n.node.GroupNodesMap[p.NGroup].Nodes {
		if x != p.NName {
			continue
		}

		n.node.GroupNodesMap[p.NGroup].Nodes = append(
			n.node.GroupNodesMap[p.NGroup].Nodes[:i-1],
			n.node.GroupNodesMap[p.NGroup].Nodes[i+1:]...,
		)
		break
	}

	if len(n.node.GroupNodesMap[p.NGroup].Nodes) != 0 {
		return &emptypb.Empty{}, nil
	}

	delete(n.node.GroupNodesMap, p.NGroup)

	for i, x := range n.node.Groups {
		if x != p.NGroup {
			continue
		}

		n.node.Groups = append(n.node.Groups[:i-1], n.node.Groups[i+1:]...)
	}

	return &emptypb.Empty{}, nil
}

func (n *NodeManager) Latency(context.Context, *wrapperspb.StringValue) (*wrapperspb.StringValue, error)

func (n *NodeManager) decodeJSON() (*Node, error) {
	pa := &Node{
		NowNode:       &Point{},
		Links:         make(map[string]*NodeLink),
		Groups:        make([]string, 0),
		GroupNodesMap: make(map[string]*NodeNodeArray),
		Nodes:         make(map[string]*Point),
	}
	_, err := os.Stat(n.configPath)
	if errors.Is(err, os.ErrNotExist) {
		return pa, n.enCodeJSON(pa)
	}

	n.lock.RLock()
	defer n.lock.RUnlock()
	data, err := ioutil.ReadFile(n.configPath)
	if err != nil {
		return nil, fmt.Errorf("read node file failed: %v", err)
	}
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, pa)
	return pa, err
}

func (n *NodeManager) enCodeJSON(pa *Node) error {
	_, err := os.Stat(path.Dir(n.configPath))
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(n.configPath), os.ModePerm)
		if err != nil {
			return fmt.Errorf("node -> enCodeJSON():MkDirAll -> %v", err)
		}
	}

	n.lock.Lock()
	defer n.lock.Unlock()

	file, err := os.OpenFile(n.configPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("open node config failed: %v", err)
	}
	defer file.Close()
	data, err := protojson.MarshalOptions{Indent: "\t"}.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal file failed: %v", err)
	}
	_, err = file.Write(data)
	return err
}

func ParseNodeConn(s *Point) (proxy.Proxy, error) {
	if s == nil {
		return nil, errors.New("not support type")
	}

	switch s.Node.(type) {
	case *Point_Shadowsocks:
		return ss.ParseConn(s)
	case *Point_Shadowsocksr:
		return ssr.ParseConn(s)
	case *Point_Vmess:
		return vm.ParseConn(s)
	}

	return nil, errors.New("not support type")
}
