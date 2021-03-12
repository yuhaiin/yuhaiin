package app

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"

	"github.com/Asutorufa/yuhaiin/net/dns"
	"github.com/Asutorufa/yuhaiin/subscr/utils"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/subscr"
)

var Entrance = struct {
	Config      *config.Setting
	LocalListen *LocalListen
	Bypass      *BypassManager
	Nodes       *utils.Node
	nodeManager *subscr.NodeManager
}{
	nodeManager: subscr.NewNodeManager(filepath.Join(config.Path, "node.json")),
}

func Init() error {
	err := RefreshNodes()
	if err != nil {
		return fmt.Errorf("RefreshNodes -> %v", err)
	}

	Entrance.Config, err = config.SettingDecodeJSON()
	if err != nil {
		return fmt.Errorf("DecodeJson -> %v", err)
	}

	s, err := NewShunt(
		Entrance.Config.Bypass.BypassFile,
		getDNS(Entrance.Config.DNS.Host, Entrance.Config.DNS.DOH, Entrance.Config.DNS.Subnet).Search,
	)
	if err != nil {
		return fmt.Errorf("create shunt failed: %v", err)
	}

	// initialize Match Controller
	Entrance.Bypass, err = NewBypassManager(
		Entrance.Config.Bypass.Enabled,
		s.Get,
		getDNS(Entrance.Config.LocalDNS.Host, Entrance.Config.LocalDNS.DOH, "").Search,
	)
	if err != nil {
		return fmt.Errorf("new Match Controller -> %v", err)
	}

	// initialize Local Servers Controller
	Entrance.LocalListen, err = NewLocalListenCon(
		WithHTTP(Entrance.Config.Proxy.HTTP),
		WithSocks5(Entrance.Config.Proxy.Socks5),
		WithRedir(Entrance.Config.Proxy.Redir),
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
	if Entrance.Config.Bypass.BypassFile != conf.Bypass.BypassFile || diffDNS(Entrance.Config.DNS, conf.DNS) {
		s, err := NewShunt(
			conf.Bypass.BypassFile,
			getDNS(conf.DNS.Host, conf.DNS.DOH, conf.DNS.Subnet).Search,
		)
		if err != nil {
			return fmt.Errorf("create shunt failed: %v", err)
		}
		Entrance.Bypass.SetMapper(s.Get)
	}

	if diffDNS(Entrance.Config.LocalDNS, conf.LocalDNS) {
		Entrance.Bypass.SetLookup(getDNS(conf.LocalDNS.Host, conf.LocalDNS.DOH, "").Search)
	}

	Entrance.Bypass.SetBypass(conf.Bypass.Enabled)

	err := Entrance.LocalListen.SetAHost(
		WithHTTP(conf.Proxy.HTTP),
		WithSocks5(conf.Proxy.Socks5),
		WithRedir(conf.Proxy.Redir),
	)
	if err != nil {
		erra = fmt.Errorf("%v\n Set Local Listener Controller Options -> %v", erra, err)
	}

	Entrance.Config = conf

	// others
	err = config.SettingEnCodeJSON(Entrance.Config)
	if err != nil {
		erra = fmt.Errorf("%v\nSaveJSON() -> %v", erra, err)
	}
	return
}

func diffDNS(old, new *config.DNS) bool {
	if old.Host != new.Host {
		return true
	}
	if old.DOH != new.DOH {
		return true
	}
	if old.Subnet != new.Subnet {
		return true
	}
	return false
}

func RefreshMapping() error {
	s, err := NewShunt(
		Entrance.Config.Bypass.BypassFile,
		getDNS(Entrance.Config.DNS.Host, Entrance.Config.DNS.DOH, Entrance.Config.DNS.Subnet).Search,
	)
	if err != nil {
		return fmt.Errorf("create shunt failed: %v", err)
	}
	Entrance.Bypass.SetMapper(s.Get)
	return nil
}

func getDNS(host string, doh bool, subnet string) dns.DNS {
	if doh {
		return dns.NewDNS(host, dns.DNSOverHTTPS, toSubnet(subnet))
	}
	return dns.NewDNS(host, dns.Normal, toSubnet(subnet))
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
	Entrance.Nodes, err = Entrance.nodeManager.GetNodesJSON()
	return
}

func ChangeNNode(group string, node string) (erra error) {
	if Entrance.Nodes.Node[group][node] == nil {
		return errors.New("not exist " + group + " - " + node)
	}
	Entrance.Nodes.NowNode = Entrance.Nodes.Node[group][node]

	err := Entrance.nodeManager.SaveNode(Entrance.Nodes)
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
	return Entrance.Nodes.NowNode.NName, Entrance.Nodes.NowNode.NGroup
}

func GetNowNodeConn() (func(string) (net.Conn, error), func(string) (net.PacketConn, error), string, error) {
	if Entrance.Nodes.NowNode == nil {
		return nil, nil, "", errors.New("NowNode is nil")
	}

	conn, packetConn, err := subscr.ParseNodeConn(Entrance.Nodes.NowNode)
	return conn, packetConn, Entrance.Nodes.NowNode.NHash, err
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
	return subscr.ParseNodeConn(Entrance.Nodes.Node[group][nodeN])
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
	err := Entrance.nodeManager.GetLinkFromInt()
	if err != nil {
		return fmt.Errorf("UpdateSub() -> %v", err)
	}
	err = RefreshNodes()
	if err != nil {
		return fmt.Errorf("RefreshNodes() -> %v", err)
	}
	return nil
}

func GetLinks() (map[string]utils.Link, error) {
	return Entrance.Nodes.Links, nil
}

func AddLink(name, style, link string) error {
	Entrance.Nodes.Links[name] = utils.Link{
		Type: style,
		Url:  link,
	}
	return Entrance.nodeManager.SaveNode(Entrance.Nodes)
}

//func AddNode(node map[string]string) error {
//	err := subscr.AddOneNode(node)
//	if err != nil {
//		return err
//	}
//	return RefreshNodes()
//}

func DeleteNode(group, name string) error {
	err := Entrance.nodeManager.DeleteOneNode(group, name)
	if err != nil {
		return err
	}
	return RefreshNodes()
}

func DeleteLink(name string) error {
	delete(Entrance.Nodes.Links, name)
	return Entrance.nodeManager.SaveNode(Entrance.Nodes)
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
