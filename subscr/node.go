package subscr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	jsonPath     = config.Path + "/node.json"
	shadowsocks  = float64(1)
	shadowsocksr = float64(2)
)

type Node struct {
	//Group   map[string]bool                   `json:"group"`
	NowNode interface{}                       `json:"nowNode"`
	Link    []string                          `json:"link"`
	Node    map[string]map[string]interface{} `json:"node"`
}

// InitJSON init the config json file
func InitJSON() error {
	pa := &Node{
		//Group:   map[string]bool{},
		NowNode: &Shadowsocks{},
		Link:    []string{},
		Node:    map[string]map[string]interface{}{},
	}
	if err := enCodeJSON(pa); err != nil {
		return err
	}
	return nil
}

func decodeJSON() (*Node, error) {
	pa := &Node{}
	file, err := os.Open(jsonPath)
	if err != nil {
		return nil, err
	}
	if json.NewDecoder(file).Decode(&pa) != nil {
		return nil, err
	}
	return pa, nil
}

func GetNodesJSON() (*Node, error) {
	return decodeJSON()
}

func enCodeJSON(pa *Node) error {
	file, err := os.Create(jsonPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	if err := enc.Encode(&pa); err != nil {
		return err
	}
	return nil
}

func SaveNode(pa *Node) error {
	return enCodeJSON(pa)
}

// GetLinkFromInt <--
func GetLinkFromInt() error {
	pa, err := decodeJSON()
	if err != nil {
		return err
	}

	//pa.Group = map[string]bool{}
	pa.Node = map[string]map[string]interface{}{}

	for _, url := range pa.Link {
		res, err := http.Get(url)
		if err != nil {
			log.Println(err)
			continue
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		dst, err := Base64d2(body)
		if err != nil {
			log.Println(err)
			continue
		}
		for _, x := range bytes.Split(dst, []byte("\n")) {
			switch {
			// Shadowsocks
			case bytes.HasPrefix(x, []byte("ss://")):
				node, err := ShadowSocksParse(x)
				if err != nil {
					log.Println(err)
					continue
				}
				if _, ok := pa.Node[node.Group]; !ok { //judge map key is exist or not
					pa.Node[node.Group] = map[string]interface{}{}
				}
				pa.Node[node.Group][node.Name] = node
			// ShadowsocksR
			case bytes.HasPrefix(x, []byte("ssr://")):
				node, err := SsrParse(x)
				if err != nil {
					log.Println(err)
					continue
				}
				if _, ok := pa.Node[node.Group]; !ok { //judge map key is exist or not
					pa.Node[node.Group] = map[string]interface{}{}
				}
				pa.Node[node.Group][node.Name] = node
			default:
				log.Println("no support " + string(x))
				continue
			}
		}
	}
	if err := enCodeJSON(pa); err != nil {
		return err
	}
	return nil
}

func AddLinkJSON(link string) error {
	pa, err := decodeJSON()
	if err != nil {
		return err
	}
	pa.Link = append(pa.Link, link)
	if err := enCodeJSON(pa); err != nil {
		return err
	}
	return nil
}

func RemoveLinkJSON(link string) error {
	pa, err := decodeJSON()
	if err != nil {
		return err
	}
	for num, oneLink := range pa.Link {
		if link == oneLink {
			pa.Link = append(pa.Link[:num], pa.Link[num+1:]...)
			break
		}
	}
	if err := enCodeJSON(pa); err != nil {
		return err
	}
	return nil
}

// GetLink <--
func GetLink() ([]string, error) {
	pa, err := decodeJSON()
	if err != nil {
		return []string{}, err
	}
	var linkTmp []string
	for _, link := range pa.Link {
		linkTmp = append(linkTmp, link)
	}
	return linkTmp, nil
}

// GetGroup <--
func GetGroup() ([]string, error) {
	pa, err := decodeJSON()
	if err != nil {
		return []string{}, err
	}
	var groupTmp []string
	for group := range pa.Node {
		groupTmp = append(groupTmp, group)
	}
	sort.Strings(groupTmp)
	return groupTmp, nil
}

// GetNode get nodes by group
func GetNode(group string) ([]string, error) {
	pa, err := decodeJSON()
	if err != nil {
		return []string{}, err
	}
	var nodeTmp []string
	for nodeRemarks := range pa.Node[group] {
		nodeTmp = append(nodeTmp, nodeRemarks)
	}
	sort.Strings(nodeTmp)
	return nodeTmp, nil
}

// ChangeNowNode <--
func ChangeNowNode(group, remarks string) error {
	pa, err := decodeJSON()
	if err != nil {
		return err
	}

	if pa.Node[group][remarks] == nil {
		return errors.New("not exist " + group + " - " + remarks)
	}
	pa.NowNode = pa.Node[group][remarks]
	if err := enCodeJSON(pa); err != nil {
		return err
	}
	return nil
}

func map2struct(s map[string]interface{}) (interface{}, error) {
	if s == nil {
		return nil, fmt.Errorf("map2struct -> %v", errors.New("argument is nil"))
	}

	var nodeType float64
	switch s["type"].(type) {
	case float64:
		nodeType = s["type"].(float64)
	default:
		return nil, fmt.Errorf("map2struct:type -> %v", errors.New("type is not float64"))
	}

	switch nodeType {
	case shadowsocks:
		node := new(Shadowsocks)
		node.Type = shadowsocks
		node.Server = s["server"].(string)
		node.Port = s["port"].(string)
		node.Method = s["method"].(string)
		node.Password = s["password"].(string)
		node.Plugin = s["plugin"].(string)
		node.PluginOpt = s["plugin_opt"].(string)
		node.Name = s["name"].(string)
		node.Group = s["group"].(string)
		return node, nil
	case shadowsocksr:
		node := new(Shadowsocksr)
		node.Type = shadowsocksr
		node.Server = s["server"].(string)
		node.Port = s["port"].(string)
		node.Method = s["method"].(string)
		node.Password = s["password"].(string)
		node.Obfs = s["obfs"].(string)
		node.Obfsparam = s["obfsparam"].(string)
		node.Protocol = s["protocol"].(string)
		node.Protoparam = s["protoparam"].(string)
		node.Name = s["name"].(string)
		node.Group = s["group"].(string)
		return node, nil
	}
	return nil, errors.New("not support type")
}

func ParseNode(s map[string]interface{}) (interface{}, error) {
	return map2struct(s)
}

// GetOneNode get one node by group and remarks
func GetOneNode(group, remarks string) (interface{}, error) {
	pa, err := decodeJSON()
	if err != nil {
		return nil, fmt.Errorf("GetOneNode:decodeJSON -> %v", err)
	}

	if pa.Node[group][remarks] == nil {
		return nil, fmt.Errorf("GetOneNode:pa.Node[group][remarks] -> %v", errors.New("node is not exist"))
	}
	currentNode := pa.Node[group][remarks].(map[string]interface{})

	node, err := map2struct(currentNode)
	if err != nil {
		return nil, fmt.Errorf("GetOneNode:map2struct -> %v", err)
	}
	return node, nil
}

// GetNowNode <--
func GetNowNode() (interface{}, error) {
	pa, err := decodeJSON()
	if err != nil {
		return nil, err
	}
	return map2struct(pa.NowNode.(map[string]interface{}))
}

func GetNowNodeGroupAndName() (name string, group string) {
	pa, err := decodeJSON()
	if err != nil {
		return "", ""
	}
	return pa.NowNode.(map[string]interface{})["name"].(string), pa.NowNode.(map[string]interface{})["group"].(string)
}

func GetOneNodeAddress(group, name string) (server, port string) {
	pa, err := decodeJSON()
	if err != nil {
		return "", ""
	}
	if pa.Node[group][name] == nil {
		return "", ""
	}
	currentNode := pa.Node[group][name].(map[string]interface{})
	return currentNode["server"].(string), currentNode["port"].(string)
}
