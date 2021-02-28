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

var Entrance = struct {
	Config      *config.Setting
	LocalListen *LocalListen
	Bypass      *BypassManager
	Nodes       *subscr.Node
}{}

func Init() error {
	err := RefreshNodes()
	if err != nil {
		return fmt.Errorf("RefreshNodes -> %v", err)
	}

	Entrance.Config, err = config.SettingDecodeJSON()
	if err != nil {
		return fmt.Errorf("DecodeJson -> %v", err)
	}

	// initialize Match Controller
	Entrance.Bypass, err = NewBypassManager(Entrance.Config.BypassFile, func(option *OptionBypassManager) {
		option.DNS.Server = Entrance.Config.DnsServer
		option.DNS.Proxy = Entrance.Config.DNSProxy
		option.DNS.DOH = Entrance.Config.DOH
		option.DNS.Subnet = toSubnet(Entrance.Config.DnsSubNet)
		option.Bypass = Entrance.Config.Bypass
		option.DirectDNS.Server = Entrance.Config.DirectDNS.Host
		option.DirectDNS.DOH = Entrance.Config.DirectDNS.DOH
	})
	if err != nil {
		return fmt.Errorf("new Match Controller -> %v", err)
	}

	// initialize Local Servers Controller
	Entrance.LocalListen, err = NewLocalListenCon(
		WithHTTP(Entrance.Config.HTTPHost),
		WithSocks5(Entrance.Config.Socks5Host),
		WithRedir(Entrance.Config.RedirHost),
		WithTCPConn(Entrance.Bypass.Forward),
		WithPacketConn(Entrance.Bypass.ForwardPacket),
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
	Entrance.Config = conf
	err := Entrance.Bypass.SetAllOption(func(option *OptionBypassManager) {
		option.DNS.Server = conf.DnsServer
		option.DNS.Proxy = conf.DNSProxy
		option.DNS.DOH = conf.DOH
		option.DNS.Subnet = toSubnet(conf.DnsSubNet)
		option.Bypass = conf.Bypass
		option.BypassPath = conf.BypassFile
		option.DirectDNS.Server = Entrance.Config.DirectDNS.Host
		option.DirectDNS.DOH = Entrance.Config.DirectDNS.DOH
	})
	if err != nil {
		erra = fmt.Errorf("%v\n Set Match Controller Options -> %v", erra, err)
	}

	err = Entrance.LocalListen.SetAHost(
		WithHTTP(conf.HTTPHost),
		WithSocks5(conf.Socks5Host),
		WithRedir(conf.RedirHost),
	)
	if err != nil {
		erra = fmt.Errorf("%v\n Set Local Listener Controller Options -> %v", erra, err)
	}
	// others
	err = config.SettingEnCodeJSON(Entrance.Config)
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
	return Entrance.Config, nil
}

/*
 *               Node
 */
func RefreshNodes() (err error) {
	Entrance.Nodes, err = subscr.GetNodesJSON()
	return
}

func ChangeNNode(group string, node string) (erra error) {
	if Entrance.Nodes.Node[group][node] == nil {
		return errors.New("not exist " + group + " - " + node)
	}
	Entrance.Nodes.NowNode = Entrance.Nodes.Node[group][node]

	err := subscr.SaveNode(Entrance.Nodes)
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
	return utils.I2String(
			Entrance.Nodes.NowNode.(map[string]interface{})["name"]),
		utils.I2String(Entrance.Nodes.NowNode.(map[string]interface{})["group"])
}

func GetNowNodeConn() (func(string) (net.Conn, error), func(string) (net.PacketConn, error), string, error) {
	if Entrance.Nodes.NowNode == nil {
		return nil, nil, "", errors.New("NowNode is nil")
	}
	switch Entrance.Nodes.NowNode.(type) {
	case map[string]interface{}:
	default:
		return nil, nil, "", errors.New("the Type is not map[string]interface{}")
	}

	var hash string
	switch Entrance.Nodes.NowNode.(map[string]interface{})["hash"].(type) {
	case string:
		hash = Entrance.Nodes.NowNode.(map[string]interface{})["hash"].(string)
	default:
		hash = "empty"
	}
	conn, packetConn, err := subscr.ParseNodeConn(Entrance.Nodes.NowNode.(map[string]interface{}))
	return conn, packetConn, hash, err
}

func GetANodes() map[string][]string {
	m := map[string][]string{}

	for key := range Entrance.Nodes.Node {
		var x []string
		for node := range Entrance.Nodes.Node[key] {
			x = append(x, node)
		}
		sort.Strings(x)
		m[key] = x
	}
	return m
}

func GetOneNodeConn(group, nodeN string) (func(string) (net.Conn, error), func(string) (net.PacketConn, error), error) {
	if Entrance.Nodes.Node[group][nodeN] == nil {
		return nil, nil, fmt.Errorf("GetOneNode:pa.Node[group][remarks] -> %v", errors.New("node is not exist"))
	}
	switch Entrance.Nodes.Node[group][nodeN].(type) {
	case map[string]interface{}:
		return subscr.ParseNodeConn(Entrance.Nodes.Node[group][nodeN].(map[string]interface{}))
	}
	return nil, nil, errors.New("the type is not map[string]interface{}")
}

func GetNodes(group string) ([]string, error) {
	var nodeTmp []string
	for nodeRemarks := range Entrance.Nodes.Node[group] {
		nodeTmp = append(nodeTmp, nodeRemarks)
	}
	sort.Strings(nodeTmp)
	return nodeTmp, nil
}

func GetGroups() ([]string, error) {
	var groupTmp []string
	for group := range Entrance.Nodes.Node {
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
	return Entrance.Nodes.Links, nil
}

func AddLink(name, style, link string) error {
	Entrance.Nodes.Links[name] = subscr.Link{
		Type: style,
		Url:  link,
	}
	return subscr.SaveNode(Entrance.Nodes)
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
	delete(Entrance.Nodes.Links, name)
	return subscr.SaveNode(Entrance.Nodes)
}

func ChangeNode() error {
	conn, packetConn, hash, err := GetNowNodeConn()
	if err != nil {
		return fmt.Errorf("GetNowNodeConn() -> %v", err)
	}
	Entrance.Bypass.SetProxy(conn, packetConn, hash)
	return nil
}

func GetDownload() uint64 {
	return Entrance.Bypass.GetDownload()
}

func GetUpload() uint64 {
	return Entrance.Bypass.GetUpload()
}
