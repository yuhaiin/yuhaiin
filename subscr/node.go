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
	"path"
	"time"

	"github.com/Asutorufa/yuhaiin/config"
)

var (
	jsonPath = config.Path + "/node.json"
)

type Node struct {
	//Group   map[string]bool                   `json:"group"`
	NowNode interface{}                       `json:"nowNode"`
	Link    []string                          `json:"link"`
	Node    map[string]map[string]interface{} `json:"node"`
}

func decodeJSON() (*Node, error) {
	file, err := os.Open(jsonPath)
	if err != nil {
		if os.IsNotExist(err) {
			pa := &Node{
				//Group:   map[string]bool{},
				NowNode: &Shadowsocks{},
				Link:    []string{},
				Node:    map[string]map[string]interface{}{},
			}
			return pa, enCodeJSON(pa)
		}
		return nil, err
	}
	pa := &Node{}
	if json.NewDecoder(file).Decode(&pa) != nil {
		return nil, err
	}
	return pa, nil
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

	nodes := map[string]map[string]interface{}{}

	for index := range pa.Link {
		oneLinkGet(pa.Link[index], nodes)
	}

	for key := range nodes {
		pa.Node[key] = nodes[key]
	}

	err = enCodeJSON(pa)
	if err != nil {
		return err
	}
	return nil
}

func oneLinkGet(url string, nodes map[string]map[string]interface{}) {
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
	dst, err := Base64DByte(body)
	if err != nil {
		log.Println(err)
		return
	}

	for _, x := range bytes.Split(dst, []byte("\n")) {
		node, group, name, err := base64ToNode(x)
		if err != nil {
			log.Println(err)
			continue
		}
		if _, ok := nodes[group]; !ok { //judge map key is exist or not
			nodes[group] = map[string]interface{}{}
		}
		nodes[group][name] = node
	}
}

func base64ToNode(str []byte) (node interface{}, group, name string, err error) {
	switch {
	// Shadowsocks
	case bytes.HasPrefix(str, []byte("ss://")):
		node, err := ShadowSocksParse(str)
		if err != nil {
			return nil, "", "", err
		}
		return node, node.NGroup, node.NName, nil
	// ShadowsocksR
	case bytes.HasPrefix(str, []byte("ssr://")):
		node, err := SsrParse(str)
		if err != nil {
			return nil, "", "", err
		}
		return node, node.NGroup, node.NName, nil
	default:
		return nil, "", "", errors.New("no support " + string(str))
	}
}

func ParseNode(s map[string]interface{}) (interface{}, error) {
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
		return map2Shadowsocks(s)
	case shadowsocksr:
		return map2Shadowsocksr(s)
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
