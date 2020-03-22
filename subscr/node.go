package subscr

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Asutorufa/SsrMicroClient/config"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
)

var (
	jsonPath     = config.GetConfigAndSQLPath() + "/node.json"
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
func InitJSON2() error {
	pa := &Node{
		//Group:   map[string]bool{},
		NowNode: nil,
		Link:    []string{},
		Node:    map[string]map[string]interface{}{},
	}
	if err := enCodeJSON2(pa); err != nil {
		return err
	}
	return nil
}

func decodeJSON2() (*Node, error) {
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

func enCodeJSON2(pa *Node) error {
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

// GetLinkFromInt <--
func GetLinkFromInt2() error {
	pa, err := decodeJSON2()
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
				pa.Node[node.Group][node.Name+" - Shadowsocks"] = node
			// ShadowsocksR
			case bytes.HasPrefix(x, []byte("ssr://")):
				node, err := SsrParse2(x)
				if err != nil {
					log.Println(err)
					continue
				}
				if _, ok := pa.Node[node.Group]; !ok { //judge map key is exist or not
					pa.Node[node.Group] = map[string]interface{}{}
				}
				pa.Node[node.Group][node.Name+" - Shadowsocksr"] = node
			default:
				log.Println("no support " + string(x))
				continue
			}
		}
	}
	if err := enCodeJSON2(pa); err != nil {
		return err
	}
	return nil
}

func AddLinkJSON2(link string) error {
	pa, err := decodeJSON2()
	if err != nil {
		return err
	}
	pa.Link = append(pa.Link, link)
	if err := enCodeJSON2(pa); err != nil {
		return err
	}
	return nil
}

func RemoveLinkJSON2(link string) error {
	pa, err := decodeJSON2()
	if err != nil {
		return err
	}
	for num, oneLink := range pa.Link {
		if link == oneLink {
			pa.Link = append(pa.Link[:num], pa.Link[num+1:]...)
			break
		}
	}
	if err := enCodeJSON2(pa); err != nil {
		return err
	}
	return nil
}

// GetLink <--
func GetLink2() ([]string, error) {
	pa, err := decodeJSON2()
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
func GetGroup2() ([]string, error) {
	pa, err := decodeJSON2()
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
func GetNode2(group string) ([]string, error) {
	pa, err := decodeJSON2()
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

// ChangeNowNode2 <--
func ChangeNowNode2(group, remarks string) error {
	pa, err := decodeJSON2()
	if err != nil {
		return err
	}

	pa.NowNode = pa.Node[group][remarks]
	if err := enCodeJSON2(pa); err != nil {
		return err
	}
	return nil
}

func map2struct(s map[string]interface{}) (interface{}, error) {
	noeType := s["type"].(float64)
	switch noeType {
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

// GetOneNode get one node by group and remarks
func GetOneNode2(group, remarks string) (interface{}, error) {
	pa, err := decodeJSON2()
	if err != nil {
		return Shadowsocksr{}, err
	}
	currentNode := pa.Node[group][remarks].(map[string]interface{})
	node, err := map2struct(currentNode)
	if err != nil {
		return nil, err
	}
	return node, nil
}

// GetNowNode <--
func GetNowNode2() (interface{}, error) {
	pa, err := decodeJSON2()
	if err != nil {
		return nil, err
	}
	return map2struct(pa.NowNode.(map[string]interface{}))
}
