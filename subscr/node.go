package subscr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	ss "github.com/Asutorufa/yuhaiin/subscr/shadowsocks"
	ssr "github.com/Asutorufa/yuhaiin/subscr/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/subscr/utils"
	"github.com/Asutorufa/yuhaiin/subscr/vmess"
)

type NodeManager struct {
	nodes      *utils.Node
	configPath string
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
		Links:   make(map[string]utils.Link),
		Node:    make(map[string]map[string]*utils.Point),
	}
	file, err := os.Open(n.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return pa, n.enCodeJSON(pa)
		}
		return nil, err
	}
	err = json.NewDecoder(file).Decode(&pa)
	if err != nil {
		return nil, err
	}

	return pa, n.enCodeJSON(pa)
}

func (n *NodeManager) GetNodes() *utils.Node {
	return n.nodes
}

func (n *NodeManager) AddLink(name, style, link string) error {
	n.nodes.Links[name] = utils.Link{
		Type: style,
		Url:  link,
	}
	return n.enCodeJSON(n.nodes)
}
func (n *NodeManager) DeleteLink(name string) error {
	delete(n.nodes.Links, name)
	return n.enCodeJSON(n.nodes)
}

func (n *NodeManager) ChangeNowNode(name, group string) {
	if n.nodes.Node[group][name] == nil {
		log.Println("not exist " + group + " - " + name)
		return
	}
	n.nodes.NowNode = n.nodes.Node[group][name]
}

func (n *NodeManager) enCodeJSON(pa *utils.Node) error {
_retry:
	file, err := os.OpenFile(n.configPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path.Dir(n.configPath), os.ModePerm)
			if err != nil {
				return fmt.Errorf("node -> enCodeJSON():MkDirAll -> %v", err)
			}
			goto _retry
		}
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "\t")
	if err := enc.Encode(&pa); err != nil {
		return err
	}
	return nil
}

// GetLinkFromInt
func (n *NodeManager) GetLinkFromInt() error {
	for key := range n.nodes.Links {
		n.oneLinkGet(n.nodes.Links[key].Url, key, n.nodes.Node)
	}

	return n.enCodeJSON(n.nodes)
}

func (n *NodeManager) oneLinkGet(url string, group string, nodes map[string]map[string]*utils.Point) {
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
	dst, err := utils.Base64DByte(body)
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

func addOneNode(p *utils.Point, nodes map[string]map[string]*utils.Point) {
	if _, ok := nodes[p.NGroup]; !ok {
		nodes[p.NGroup] = make(map[string]*utils.Point)
	}
	nodes[p.NGroup][p.NName] = p
}

func printNodes(nodes map[string]map[string]interface{}) {
	for key := range nodes {
		fmt.Println("Group:", key)
		for nodeKey := range nodes[key] {
			fmt.Println("Name:", nodeKey)
		}
		fmt.Println("")
	}
}

func deleteAllRemoteNodes(nodes map[string]map[string]*utils.Point) {
	for key := range nodes {
		deleteRemoteNodes(nodes, key)
	}
}

func deleteRemoteNodes(nodes map[string]map[string]*utils.Point, key string) {
	for nodeKey := range nodes[key] {
		if nodes[key][nodeKey].NOrigin == utils.Remote {
			delete(nodes[key], nodeKey)
		}
	}
	if len(nodes[key]) == 0 {
		delete(nodes, key)
	}
}

func (n *NodeManager) DeleteOneNode(group, name string) error {
	deleteOneNode(group, name, n.nodes.Node)
	return n.enCodeJSON(n.nodes)
}

func deleteOneNode(group, name string, nodes map[string]map[string]*utils.Point) {
	if _, ok := nodes[group]; !ok {
		return
	}
	if _, ok := nodes[group][name]; !ok {
		return
	}
	delete(nodes[group], name)

	if len(nodes[group]) == 0 {
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

// GetNowNode
func (n *NodeManager) GetNowNode() *utils.Point {
	return n.nodes.NowNode
}

func ParseNodeConn(s *utils.Point) (func(string) (net.Conn, error), func(string) (net.PacketConn, error), error) {
	switch s.NType {
	case utils.Shadowsocks:
		return ss.ParseConn(s)
	case utils.Shadowsocksr:
		return ssr.ParseConn(s)
	case utils.Vmess:
		return vmess.ParseConn(s)
	}
	return nil, nil, errors.New("not support type")
}
