package subscr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/Asutorufa/SsrMicroClient/net/proxy/socks5/client"
)

// ConfigSample config sample json struct
type ConfigSample struct {
	Group   map[string]bool                    `json:"group"`
	NowNode Shadowsocksr                       `json:"nowNode"`
	Link    []string                           `json:"link"`
	Node    map[string]map[string]Shadowsocksr `json:"node"`
}

// InitJSON init the config json file
func InitJSON(configPath string) error {
	pa := &ConfigSample{
		Group:   map[string]bool{},
		NowNode: Shadowsocksr{},
		Link:    []string{},
		Node:    map[string]map[string]Shadowsocksr{},
	}
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

func decodeJSON(configPath string) (*ConfigSample, error) {
	pa := &ConfigSample{}
	file, err := os.Open(configPath + "/node.json")
	if err != nil {
		return &ConfigSample{}, err
	}
	if json.NewDecoder(file).Decode(&pa) != nil {
		return &ConfigSample{}, err
	}
	return pa, nil
}

func enCodeJSON(configPath string, pa *ConfigSample) error {
	file, err := os.Create(configPath + "/node.json")
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
func GetLinkFromInt(configPath string) ([]string, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return []string{}, err
	}
	var allLink string
	for _, url := range pa.Link {
		res, err := http.Get(url)
		if err != nil {
			log.Println(err)
			continue
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []string{}, err
		}
		allLink += Base64d(string(body))
	}
	return strings.Split(allLink, "\n"), nil
}

// GetLinkFromIntCrossProxy Get Link From Internet across your own proxy
func GetLinkFromIntCrossProxy(configPath string) ([]string, error) {
	setting, err := config.SettingDecodeJSON(configPath)
	if err != nil {
		return []string{}, err
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		x := &socks5client.Client{Server: setting.LocalAddress, Port: setting.LocalPort, Address: addr}
		return x.NewSocks5Client()
	}
	tr := http.Transport{
		DialContext: dialContext,
	}
	newClient := &http.Client{Transport: &tr}

	pa, err := decodeJSON(configPath)
	if err != nil {
		return []string{}, err
	}
	var allLink string
	for _, url := range pa.Link {
		res, err := newClient.Get(url)
		if err != nil {
			log.Println(err)
			continue
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return []string{}, err
		}
		allLink += Base64d(string(body))
	}
	return strings.Split(allLink, "\n"), nil
}

func AddLinkJSON(link, configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	pa.Link = append(pa.Link, link)
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

func RemoveLinkJSON(link, configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	for num, oneLink := range pa.Link {
		if link == oneLink {
			pa.Link = append(pa.Link[:num], pa.Link[num+1:]...)
			break
		}
	}
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// GetLink <--
func GetLink(configPath string) ([]string, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return []string{}, err
	}
	var linkTmp []string
	for _, link := range pa.Link {
		linkTmp = append(linkTmp, link)
	}
	return linkTmp, nil
}

// SsrJSON reset all node from link
func SsrJSON(configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	pa.Group = map[string]bool{}
	pa.Node = map[string]map[string]Shadowsocksr{}
	allNode, err := GetLinkFromInt(configPath)
	if err != nil {
		return err
	}
	for num, oneNode := range allNode {
		nodeGet, err := SsrParse(oneNode)
		if err != nil {
			return err
		}
		if len(nodeGet) == 0 {
			continue
		}
		nodeJSON := &Shadowsocksr{
			ID:         num,
			Server:     nodeGet["server"],
			Port:       nodeGet["serverPort"],
			Protocol:   nodeGet["protocol"],
			Method:     nodeGet["method"],
			Obfs:       nodeGet["obfs"],
			Password:   nodeGet["password"],
			Obfsparam:  nodeGet["obfsparam"],
			Protoparam: nodeGet["protoparam"],
			Name:       nodeGet["remarks"],
			Group:      nodeGet["group"],
		}
		if !pa.Group[nodeJSON.Group] {
			pa.Group[nodeJSON.Group] = true
		}
		if _, ok := pa.Node[nodeJSON.Group]; !ok { //judge map key is exist or not
			pa.Node[nodeJSON.Group] = map[string]Shadowsocksr{}
		}
		pa.Node[nodeJSON.Group][nodeJSON.Name] = *nodeJSON
	}
	// js, err := json.MarshalIndent(pa, "", "\t")
	// if err != nil {
	// 	return err
	// }
	// log.Println(pa)
	// log.Println(string(js))
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// GetGroup <--
func GetGroup(configPath string) ([]string, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return []string{}, err
	}
	var groupTmp []string
	for group := range pa.Node {
		//fmt.Println(num, group)
		groupTmp = append(groupTmp, group)
	}
	sort.Strings(groupTmp)
	return groupTmp, nil
}

// GetNode get nodes by group
func GetNode(configPath, group string) ([]string, error) {
	pa, err := decodeJSON(configPath)
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
func ChangeNowNode(configPath, group, remarks string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}

	pa.NowNode = pa.Node[group][remarks]
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// GetOneNode get one node by group and remarks
func GetOneNode(configPath, group, remarks string) (Shadowsocksr, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return Shadowsocksr{}, err
	}
	return pa.Node[group][remarks], nil
}

// GetNowNode <--
func GetNowNode(configPath string) (map[string]string, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return map[string]string{}, err
	}
	node := make(map[string]string)
	node["remarks"] = pa.NowNode.Name
	node["server"] = pa.NowNode.Server
	node["serverPort"] = pa.NowNode.Port
	node["protocol"] = pa.NowNode.Protocol
	node["method"] = pa.NowNode.Method
	node["obfs"] = pa.NowNode.Obfs
	node["password"] = pa.NowNode.Password
	node["obfsparam"] = pa.NowNode.Obfsparam
	node["protoparam"] = pa.NowNode.Protoparam
	node["group"] = pa.NowNode.Group
	return node, nil
}

/***************************
				No Use
*******************************/

// SelectNode <--
func SelectNode(configPath string) (Shadowsocksr, error) {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return Shadowsocksr{}, err
	}
selectgroup:
	groupTmp := make(map[int]string)
	num := 1
	for group := range pa.Node {
		fmt.Println(num, group)
		groupTmp[num] = group
		num++
	}
	var selectGroup int
	_, _ = fmt.Scanln(&selectGroup)
	if selectGroup < 0 || selectGroup > num-1 {
		fmt.Println("select error")
		goto selectgroup
	} else if selectGroup == 0 {
		return Shadowsocksr{}, nil
	} else {
	selectnode:
		num = 1
		nodeTmp := make(map[int]string)
		for nodeRemarks := range pa.Node[groupTmp[selectGroup]] {
			fmt.Println(num, nodeRemarks)
			nodeTmp[num] = nodeRemarks
			num++
		}
		var selectNode int
		_, _ = fmt.Scanln(&selectNode)
		if selectNode < 0 || selectNode > num-1 {
			fmt.Println("select error")
			goto selectnode
		} else if selectNode == 0 {
			goto selectgroup
		} else {
			return pa.Node[groupTmp[selectGroup]][nodeTmp[selectNode]], nil
		}
	}
}

// ChangeNowNode <--
func ChangeNowNode3(configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	node, err := SelectNode(configPath)
	if err != nil {
		return err
	}
	if node.Server == "" {
		return nil
	}
	pa.NowNode = node
	if err := enCodeJSON(configPath, pa); err != nil {
		return err
	}
	return nil
}

// RemoveLinkJSON remove link for other package
func RemoveLinkJSON3(configPath string) error {
	pa, err := decodeJSON(configPath)
	if err != nil {
		return err
	}
	var linkSum int
	var link string
	for linkSum, link = range pa.Link {
		fmt.Println(strconv.Itoa(linkSum+1) + "." + link)
	}
	var num int
	if _, err = fmt.Scanln(&num); err != nil {
		return err
	}

	if num < 1 || num > linkSum+1 {
		return nil
	}
	if err := RemoveLinkJSON(pa.Link[num-1], configPath); err != nil {
		return err
	}
	return nil
}

// AddLinkJSON for other package to add link
func AddLinkJSON3(configPath string) error {
	var link string
	_, _ = fmt.Scanln(&link)
	_ = AddLinkJSON(link, configPath)
	return nil
}
