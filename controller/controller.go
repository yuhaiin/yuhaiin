package controller

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sort"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/subscr"
)

var (
	ConFig         *config.Setting
	LocalListenCon *LocalListen
	MatchCon       *MatchController
	Nodes          *subscr.Node
)

func Init() error {
	err := RefreshNodes()
	if err != nil {
		return fmt.Errorf("RefreshNodes -> %v", err)
	}

	ConFig, err = config.SettingDecodeJSON()
	if err != nil {
		return fmt.Errorf("DecodeJson -> %v", err)
	}

	// initialize Match Controller
	MatchCon, err = NewMatchCon(ConFig.BypassFile, func(option *OptionMatchCon) {
		option.DNS.Server = ConFig.DnsServer
		option.DNS.Proxy = ConFig.DNSProxy
		option.DNS.DOH = ConFig.DOH
		option.DNS.Subnet = toSubnet(ConFig.DnsSubNet)
		option.Bypass = ConFig.Bypass
		option.DirectDNS.Server = ConFig.DirectDNS.Host
		option.DirectDNS.DOH = ConFig.DirectDNS.DOH
	})
	if err != nil {
		return fmt.Errorf("new Match Controller -> %v", err)
	}

	// initialize Local Servers Controller
	LocalListenCon, err = NewLocalListenCon(
		WithHTTP(ConFig.HTTPHost),
		WithSocks5(ConFig.Socks5Host),
		WithRedir(ConFig.RedirHost),
		WithTCPConn(MatchCon.Forward),
	)
	if err != nil {
		return fmt.Errorf("new Local Listener Controller -> %v", err)
	}

	_ = ChangeNode()
	return nil
}

/*
 *         CONFIG
 */
func SetConFig(conf *config.Setting) (erra error) {
	ConFig = conf
	err := MatchCon.SetAllOption(func(option *OptionMatchCon) {
		option.DNS.Server = conf.DnsServer
		option.DNS.Proxy = conf.DNSProxy
		option.DNS.DOH = conf.DOH
		option.DNS.Subnet = toSubnet(conf.DnsSubNet)
		option.Bypass = conf.Bypass
		option.BypassPath = conf.BypassFile
		option.DirectDNS.Server = ConFig.DirectDNS.Host
		option.DirectDNS.DOH = ConFig.DirectDNS.DOH
	})
	if err != nil {
		erra = fmt.Errorf("%v\n Set Match Controller Options -> %v", erra, err)
	}

	err = LocalListenCon.SetAHost(
		WithHTTP(conf.HTTPHost),
		WithSocks5(conf.Socks5Host),
		WithRedir(conf.RedirHost),
	)
	if err != nil {
		erra = fmt.Errorf("%v\n Set Local Listener Controller Options -> %v", erra, err)
	}
	// others
	err = config.SettingEnCodeJSON(ConFig)
	if err != nil {
		erra = fmt.Errorf("%v\nSaveJSON() -> %v", erra, err)
	}
	return
}

func toSubnet(s string) *net.IPNet {
	_, subnet, err := net.ParseCIDR(s)
	if err != nil {
		if net.ParseIP(s).To4() != nil {
			_, subnet, _ = net.ParseCIDR(s + "/32")
		}

		if net.ParseIP(s).To16() != nil {
			_, subnet, _ = net.ParseCIDR(s + "/128")
		}
	}
	return subnet
}

func GetConfig() (*config.Setting, error) {
	return ConFig, nil
}

/*
 *               Node
 */
func RefreshNodes() (err error) {
	Nodes, err = subscr.GetNodesJSON()
	return
}

func ChangeNNode(group string, node string) (erra error) {
	if Nodes.Node[group][node] == nil {
		return errors.New("not exist " + group + " - " + node)
	}
	Nodes.NowNode = Nodes.Node[group][node]

	err := subscr.SaveNode(Nodes)
	if err != nil {
		erra = fmt.Errorf("%v\nSaveNode() -> %v", erra, err)
	}

	err = ChangeNode()
	if err != nil {
		erra = fmt.Errorf("%v\nChangeNode -> %v", erra, err)
	}
	return
}

func GetNNodeAndNGroup() (node string, group string) {
	return Nodes.NowNode.(map[string]interface{})["name"].(string), Nodes.NowNode.(map[string]interface{})["group"].(string)
}

func GetNowNode() (interface{}, string, error) {
	if Nodes.NowNode == nil {
		return nil, "", errors.New("NowNode is nil")
	}
	var hash string
	if Nodes.NowNode.(map[string]interface{})["hash"] == nil {
		log.Println("hash is nil")
		hash = "empty"
	} else {
		hash = Nodes.NowNode.(map[string]interface{})["hash"].(string)
	}
	node, err := subscr.ParseNode(Nodes.NowNode.(map[string]interface{}))
	return node, hash, err
}

func GetOneNode(group, nodeN string) (interface{}, error) {
	if Nodes.Node[group][nodeN] == nil {
		return nil, fmt.Errorf("GetOneNode:pa.Node[group][remarks] -> %v", errors.New("node is not exist"))
	}
	currentNode := Nodes.Node[group][nodeN].(map[string]interface{})

	node, err := subscr.ParseNode(currentNode)
	if err != nil {
		return nil, fmt.Errorf("GetOneNode:map2struct -> %v", err)
	}
	return node, nil
}

func GetNodes(group string) ([]string, error) {

	var nodeTmp []string
	for nodeRemarks := range Nodes.Node[group] {
		nodeTmp = append(nodeTmp, nodeRemarks)
	}
	sort.Strings(nodeTmp)
	return nodeTmp, nil
}

func GetGroups() ([]string, error) {
	var groupTmp []string
	for group := range Nodes.Node {
		groupTmp = append(groupTmp, group)
	}
	sort.Strings(groupTmp)
	return groupTmp, nil
}

func UpdateSub() error {
	err := subscr.GetLinkFromInt()
	if err != nil {
		return fmt.Errorf("UpdateSub() -> %v", err)
	}
	err = RefreshNodes()
	if err != nil {
		return fmt.Errorf("RefreshNodes() -> %v", err)
	}
	return nil
}

func GetLinks() ([]string, error) {
	var linkTmp []string
	for _, link := range Nodes.Link {
		linkTmp = append(linkTmp, link)
	}
	return linkTmp, nil
}

func AddLink(str string) error {
	Nodes.Link = append(Nodes.Link, str)
	return subscr.SaveNode(Nodes)
}

func DeleteLink(str string) error {
	for index := range Nodes.Link {
		if str == Nodes.Link[index] {
			Nodes.Link = append(Nodes.Link[:index], Nodes.Link[index+1:]...)
			break
		}
	}
	return subscr.SaveNode(Nodes)
}

func ChangeNode() error {
	nod, hash, err := GetNowNode()
	if err != nil {
		return fmt.Errorf("GetNowNode() -> %v", err)
	}
	err = MatchCon.ChangeNode(nod, hash)
	if err != nil {
		return fmt.Errorf("ChangeNode -> %v", err)
	}
	return nil
}
