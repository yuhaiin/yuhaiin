package subscr

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	ss "github.com/Asutorufa/yuhaiin/pkg/subscr/shadowsocks"
	ssr "github.com/Asutorufa/yuhaiin/pkg/subscr/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/vmess"
	"google.golang.org/protobuf/encoding/protojson"
)

type NodeManager struct {
	nodes      *utils.Node
	configPath string

	lock sync.RWMutex
}

func NewNodeManager(configPath string) (n *NodeManager, err error) {
	n = &NodeManager{
		configPath: configPath,
	}
	n.nodes, err = n.decodeJSON()
	return
}

func (n *NodeManager) decodeJSON() (*utils.Node, error) {
	pa := &utils.Node{
		NowNode: &utils.Point{},
		Links:   make(map[string]*utils.NodeLink),
		Nodes:   make(map[string]*utils.NodeNode),
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

func (n *NodeManager) GetNodes() *utils.Node {
	return n.nodes
}

func (n *NodeManager) AddLink(name, style, link string) error {
	n.nodes.Links[name] = &utils.NodeLink{
		Type: style,
		Url:  link,
	}
	return n.enCodeJSON(n.nodes)
}

func (n *NodeManager) DeleteLink(name string) error {
	delete(n.nodes.Links, name)
	return n.enCodeJSON(n.nodes)
}

func (n *NodeManager) ChangeNowNode(name, group string) error {
	if n.nodes.Nodes[group] == nil {
		return errors.New("not exist group" + group)
	}
	if n.nodes.Nodes[group].Node[name] == nil {
		return errors.New("not exist node" + name)

	}
	n.nodes.NowNode = n.nodes.Nodes[group].Node[name]
	return n.enCodeJSON(n.nodes)
}

func (n *NodeManager) enCodeJSON(pa *utils.Node) error {
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

// GetLinkFromInt update subscribe
func (n *NodeManager) GetLinkFromInt() error {
	if n.nodes.Links == nil {
		n.nodes.Links = make(map[string]*utils.NodeLink)
	}
	if n.nodes.Nodes == nil {
		n.nodes.Nodes = make(map[string]*utils.NodeNode)
	}
	for key := range n.nodes.Links {
		n.oneLinkGet(n.nodes.Links[key].Url, key, n.nodes.Nodes)
	}

	return n.enCodeJSON(n.nodes)
}

func (n *NodeManager) oneLinkGet(url string, group string, nodes map[string]*utils.NodeNode) {
	client := http.Client{Timeout: time.Second * 30}
	res, err := client.Get(url)
	if err != nil {
		log.Println(err)
		return
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return
	}
	dst, err := utils.DecodeBytesBase64(body)
	if err != nil {
		log.Println(err)
		return
	}
	deleteRemoteNodes(nodes, group)
	for _, x := range bytes.Split(dst, []byte("\n")) {
		node, err := parseUrl(x, group)
		if err != nil {
			log.Println(err)
			continue
		}
		addOneNode(node, nodes)
	}
}

func addOneNode(p *utils.Point, nodes map[string]*utils.NodeNode) {
	if _, ok := nodes[p.NGroup]; !ok {
		nodes[p.NGroup] = &utils.NodeNode{
			Node: make(map[string]*utils.Point),
		}
	}
	if nodes[p.NGroup].Node == nil {
		nodes[p.NGroup].Node = make(map[string]*utils.Point)
	}

	nodes[p.NGroup].Node[p.NName] = p
}

func deleteRemoteNodes(nodes map[string]*utils.NodeNode, key string) {
	if nodes[key] == nil {
		return
	}
	if nodes[key].Node == nil {
		delete(nodes, key)
		return
	}

	for nodeKey := range nodes[key].Node {
		if nodes[key].Node[nodeKey].NOrigin == utils.Point_remote {
			delete(nodes, nodeKey)
		}
	}
	if len(nodes[key].Node) == 0 {
		delete(nodes, key)
	}
}

func (n *NodeManager) DeleteOneNode(group, name string) error {
	deleteOneNode(group, name, n.nodes.Nodes)
	return n.enCodeJSON(n.nodes)
}

func deleteOneNode(group, name string, nodes map[string]*utils.NodeNode) {
	if x, ok := nodes[group]; !ok {
		if _, ok := x.Node[name]; !ok {
			return
		}
	}

	delete(nodes[group].Node, name)

	if len(nodes[group].Node) == 0 {
		delete(nodes, group)
	}
}

func parseUrl(str []byte, group string) (node *utils.Point, err error) {
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
		node, err := vmess.ParseLink(str, group)
		if err != nil {
			return nil, err
		}
		return node, nil
	default:
		return nil, errors.New("no support " + string(str))
	}
}

// GetNowNode return current node point
func (n *NodeManager) GetNowNode() *utils.Point {
	return n.nodes.NowNode
}

func ParseNodeConn(s *utils.Point) (proxy.Proxy, error) {
	if s == nil {
		return nil, errors.New("not support type")
	}

	switch s.Node.(type) {
	case *utils.Point_Shadowsocks:
		return ss.ParseConn(s)
	case *utils.Point_Shadowsocksr:
		return ssr.ParseConn(s)
	case *utils.Point_Vmess:
		return vmess.ParseConn(s)
	}

	return nil, errors.New("not support type")
}
