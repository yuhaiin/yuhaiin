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
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/config"
	ss "github.com/Asutorufa/yuhaiin/subscr/shadowsocks"
	ssr "github.com/Asutorufa/yuhaiin/subscr/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/subscr/utils"
	"github.com/Asutorufa/yuhaiin/subscr/vmess"
)

var (
	jsonPath = config.Path + "/node.json"
)

type Link struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}

type Node struct {
	NowNode interface{}                       `json:"nowNode"`
	Link    []string                          `json:"link"`
	Links   map[string]Link                   `json:"links"`
	Node    map[string]map[string]interface{} `json:"node"`
}

func decodeJSON() (*Node, error) {
	pa := &Node{
		NowNode: map[string]interface{}{},
		Link:    []string{},
		Links:   map[string]Link{},
		Node:    map[string]map[string]interface{}{},
	}
	file, err := os.Open(jsonPath)
	if err != nil {
		if os.IsNotExist(err) {
			return pa, enCodeJSON(pa)
		}
		return nil, err
	}
	err = json.NewDecoder(file).Decode(&pa)
	if err != nil {
		return nil, err
	}

	//TODO Deprecated
	for index := range pa.Link {
		pa.Links[pa.Link[index]] = Link{
			Url: pa.Link[index],
		}
	}
	pa.Link = pa.Link[:0]

	return pa, enCodeJSON(pa)
}

func GetNodesJSON() (*Node, error) {
	return decodeJSON()
}

func enCodeJSON(pa *Node) error {
_retry:
	file, err := os.OpenFile(jsonPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path.Dir(jsonPath), os.ModePerm)
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

func SaveNode(pa *Node) error {
	return enCodeJSON(pa)
}

// GetLinkFromInt
func GetLinkFromInt() error {
	pa, err := decodeJSON()
	if err != nil {
		return err
	}

	for key := range pa.Links {
		oneLinkGet(pa.Links[key].Url, key, pa.Node)
	}

	err = enCodeJSON(pa)
	if err != nil {
		return err
	}
	return nil
}

func oneLinkGet(url string, group string, nodes map[string]map[string]interface{}) {
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
		node, name, err := base64ToNode(x, group)
		if err != nil {
			log.Println(err)
			continue
		}
		addOneNode(node, group, name, nodes)
	}
}

func AddOneNode(node map[string]string) error {
	pa, err := decodeJSON()
	if err != nil {
		return err
	}
	tYPE, err := strconv.ParseFloat(node["type"], 64)
	if err != nil {
		return err
	}
	newNode := map[string]interface{}{
		"type": tYPE,
	}
	for key := range node {
		newNode[key] = node[key]
	}
	no, err := parseNodeManual(newNode)
	if err != nil {
		return err
	}
	addOneNode(no, node["name"], node["group"], pa.Node)
	return enCodeJSON(pa)
}

func addOneNode(node interface{}, group, name string, nodes map[string]map[string]interface{}) {
	if _, ok := nodes[group]; !ok {
		nodes[group] = map[string]interface{}{}
	}
	nodes[group][name] = node
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

func deleteAllRemoteNodes(nodes map[string]map[string]interface{}) {
	for key := range nodes {
		deleteRemoteNodes(nodes, key)
	}
}

func deleteRemoteNodes(nodes map[string]map[string]interface{}, key string) {
	for nodeKey := range nodes[key] {
		if checkRemote(nodes[key][nodeKey]) {
			delete(nodes[key], nodeKey)
		}
	}
	for range nodes[key] {
		return
	}
	delete(nodes, key)
}

func checkRemote(node interface{}) bool {
	switch node.(type) {
	case map[string]interface{}:
	default:
		return false
	}

	if _, ok := node.(map[string]interface{})["n_origin"]; !ok {
		return false
	}

	switch node.(map[string]interface{})["n_origin"].(type) {
	case float64:
	default:
		return false
	}

	if node.(map[string]interface{})["n_origin"].(float64) == utils.Remote {
		return true
	}
	return false
}

func DeleteOneNode(group, name string) error {
	pa, err := decodeJSON()
	if err != nil {
		return err
	}
	deleteOneNode(group, name, pa.Node)
	return enCodeJSON(pa)
}

func deleteOneNode(group, name string, nodes map[string]map[string]interface{}) {
	if _, ok := nodes[group]; !ok {
		return
	}
	if _, ok := nodes[group][name]; !ok {
		return
	}
	delete(nodes[group], name)
	for range nodes[group] {
		return
	}
	delete(nodes, group)
}

func base64ToNode(str []byte, group string) (node interface{}, name string, err error) {
	switch {
	// Shadowsocks
	case bytes.HasPrefix(str, []byte("ss://")):
		node, err := ss.ParseLink(str, group)
		if err != nil {
			return nil, "", err
		}
		return node, node.NName, nil
	// ShadowsocksR
	case bytes.HasPrefix(str, []byte("ssr://")):
		node, err := ssr.ParseLink(str, group)
		if err != nil {
			return nil, "", err
		}
		return node, node.NName, nil
	case bytes.HasPrefix(str, []byte("vmess://")):
		node, err := vmess.ParseLink(str, group)
		if err != nil {
			return nil, "", err
		}
		return node, node.NName, nil
	default:
		return nil, "", errors.New("no support " + string(str))
	}
}

func ParseNode(s map[string]interface{}) (interface{}, error) {
	nodeType, err := checkType(s)
	if err != nil {
		return nil, err
	}

	switch nodeType {
	case utils.Shadowsocks:
		return ss.ParseMap(s)
	case utils.Shadowsocksr:
		return ssr.ParseMap(s)
	case utils.Vmess:
		return vmess.ParseMap(s)
	}
	return nil, errors.New("not support type")
}

func parseNodeManual(s map[string]interface{}) (interface{}, error) {
	nodeType, err := checkType(s)
	if err != nil {
		return nil, err
	}

	switch nodeType {
	case utils.Shadowsocks:
		return ss.ParseMapManual(s)
	case utils.Shadowsocksr:
		return ssr.ParseMapManual(s)
	case utils.Vmess:
	}
	return nil, errors.New("not support type")
}

// GetNowNode
func GetNowNode() (interface{}, error) {
	pa, err := decodeJSON()
	if err != nil {
		return nil, err
	}
	return ParseNode(pa.NowNode.(map[string]interface{}))
}

func ParseNodeConn(s map[string]interface{}) (func(string) (net.Conn, error), error) {
	nodeType, err := checkType(s)
	if err != nil {
		return nil, err
	}
	switch nodeType {
	case utils.Shadowsocks:
		return ss.ParseConn(s)
	case utils.Shadowsocksr:
		return ssr.ParseConn(s)
	case utils.Vmess:
		return vmess.ParseConn(s)
	}
	return nil, errors.New("not support type")
}

func checkType(s map[string]interface{}) (Type float64, err error) {
	if s == nil {
		return 0, fmt.Errorf("map2struct -> %v", errors.New("argument is nil"))
	}

	//TODO Deprecated
	switch s["type"].(type) {
	case float64:
		Type = s["type"].(float64)
		return
	default:
	}

	switch s["n_type"].(type) {
	case float64:
		Type = s["n_type"].(float64)
	default:
		return 0, fmt.Errorf("map2struct:type -> %v", errors.New("type is not float64"))
	}
	return
}
