package app

import (
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/subscr"
	"github.com/Asutorufa/yuhaiin/subscr/utils"
)

var (
	ConFig         *config.Setting
	LocalListenCon *LocalListen
	MatchCon       *BypassManager
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
	MatchCon, err = NewBypassManager(ConFig.BypassFile, func(option *OptionBypassManager) {
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
		WithPacketConn(MatchCon.ForwardPacket),
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
	err := MatchCon.SetAllOption(func(option *OptionBypassManager) {
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
	return utils.I2String(Nodes.NowNode.(map[string]interface{})["name"]), utils.I2String(Nodes.NowNode.(map[string]interface{})["group"])
}

func GetNowNodeConn() (func(string) (net.Conn, error), func(string) (net.PacketConn, error), string, error) {
	if Nodes.NowNode == nil {
		return nil, nil, "", errors.New("NowNode is nil")
	}
	switch Nodes.NowNode.(type) {
	case map[string]interface{}:
	default:
		return nil, nil, "", errors.New("the Type is not map[string]interface{}")
	}

	var hash string
	switch Nodes.NowNode.(map[string]interface{})["hash"].(type) {
	case string:
		hash = Nodes.NowNode.(map[string]interface{})["hash"].(string)
	default:
		hash = "empty"
	}
	conn, packetConn, err := subscr.ParseNodeConn(Nodes.NowNode.(map[string]interface{}))
	return conn, packetConn, hash, err
}

func GetANodes() map[string][]string {
	m := map[string][]string{}

	for key := range Nodes.Node {
		var x []string
		for node := range Nodes.Node[key] {
			x = append(x, node)
		}
		sort.Strings(x)
		m[key] = x
	}
	return m
}

func GetOneNodeConn(group, nodeN string) (func(string) (net.Conn, error), func(string) (net.PacketConn, error), error) {
	if Nodes.Node[group][nodeN] == nil {
		return nil, nil, fmt.Errorf("GetOneNode:pa.Node[group][remarks] -> %v", errors.New("node is not exist"))
	}
	switch Nodes.Node[group][nodeN].(type) {
	case map[string]interface{}:
		return subscr.ParseNodeConn(Nodes.Node[group][nodeN].(map[string]interface{}))
	}
	return nil, nil, errors.New("the type is not map[string]interface{}")
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

func GetLinks() (map[string]subscr.Link, error) {
	return Nodes.Links, nil
}

func AddLink(name, tYPE, link string) error {
	Nodes.Links[name] = subscr.Link{
		Type: tYPE,
		Url:  link,
	}
	return subscr.SaveNode(Nodes)
}

func AddNode(node map[string]string) error {
	err := subscr.AddOneNode(node)
	if err != nil {
		return err
	}
	return RefreshNodes()
}

func DeleteNode(group, name string) error {
	err := subscr.DeleteOneNode(group, name)
	if err != nil {
		return err
	}
	return RefreshNodes()
}

func DeleteLink(name string) error {
	delete(Nodes.Links, name)
	return subscr.SaveNode(Nodes)
}

func ChangeNode() error {
	conn, packetConn, hash, err := GetNowNodeConn()
	if err != nil {
		return fmt.Errorf("GetNowNodeConn() -> %v", err)
	}
	MatchCon.SetProxy(conn, packetConn, hash)
	return nil
}
