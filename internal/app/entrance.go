package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

type Entrance struct {
	Config      *config.Setting
	LocalListen *LocalListen
	Bypass      *BypassManager
	nodeManager *subscr.NodeManager
	shunt       *Shunt

	nodeHash string
}

func NewEntrance() (e *Entrance, err error) {
	e = &Entrance{}
	e.nodeManager, err = subscr.NewNodeManager(filepath.Join(config.Path, "node.json"))
	if err != nil {
		return nil, fmt.Errorf("refresh node failed: %v", err)
	}

	e.Config, err = config.SettingDecodeJSON()
	if err != nil {
		return nil, fmt.Errorf("get config failed: %v", err)
	}

	e.shunt, err = NewShunt(e.Config.Bypass.BypassFile, getDNS(e.Config.DNS).Search)
	if err != nil {
		return nil, fmt.Errorf("create shunt failed: %v", err)
	}

	// initialize Match Controller
	e.Bypass, err = NewBypassManager(e.Config.Bypass.Enabled, e.shunt.Get, getDNS(e.Config.LocalDNS).Search)
	if err != nil {
		return nil, fmt.Errorf("create new bypass service failed: %v", err)
	}

	return e, nil
}

func (e *Entrance) Start() (err error) {
	// initialize Local Servers Controller
	e.LocalListen, err = NewLocalListenCon(
		WithHTTP(e.Config.Proxy.HTTP),
		WithSocks5(e.Config.Proxy.Socks5),
		WithRedir(e.Config.Proxy.Redir),
		WithTCPConn(e.Bypass.Forward),
		WithPacketConn(e.Bypass.ForwardPacket),
	)
	if err != nil {
		return fmt.Errorf("create local listener failed: %v", err)
	}

	err = e.ChangeNode()
	if err != nil {
		log.Printf("changer node failed: %v\n", err)
	}
	return
}

func (e *Entrance) SetConFig(conf *config.Setting) (erra error) {
	var err error
	if e.Config.Bypass.BypassFile != conf.Bypass.BypassFile {
		e.shunt.SetFile(conf.Bypass.BypassFile)
	}

	if diffDNS(e.Config.DNS, conf.DNS) {
		e.shunt.SetLookup(getDNS(conf.DNS).Search)
	}

	if diffDNS(e.Config.LocalDNS, conf.LocalDNS) ||
		e.Config.Bypass.Enabled != conf.Bypass.Enabled {
		e.Bypass, err = NewBypassManager(e.Config.Bypass.Enabled, e.shunt.Get, getDNS(e.Config.LocalDNS).Search)
		if err != nil {
			erra = fmt.Errorf("%v\nlocal listener apply config failed: %v", erra, err)
		}
	}

	err = e.LocalListen.SetAHost(WithHTTP(conf.Proxy.HTTP),
		WithSocks5(conf.Proxy.Socks5), WithRedir(conf.Proxy.Redir))
	if err != nil {
		erra = fmt.Errorf("%v\nlocal listener apply config failed: %v", erra, err)
	}

	e.Config = conf

	err = config.SettingEnCodeJSON(e.Config)
	if err != nil {
		erra = fmt.Errorf("%v\nsave setting failed: %v", erra, err)
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

func (e *Entrance) RefreshMapping() error {
	return e.shunt.RefreshMapping()
}

func getDNS(dc *config.DNS) dns.DNS {
	if dc.DOH {
		return dns.NewDNS(dc.Host, dns.DNSOverHTTPS, toSubnet(dc.Subnet))
	}
	return dns.NewDNS(dc.Host, dns.Normal, toSubnet(dc.Subnet))
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

func (e *Entrance) GetConfig() (*config.Setting, error) {
	return e.Config, nil
}

func (e *Entrance) ChangeNNode(group string, node string) (err error) {
	err = e.nodeManager.ChangeNowNode(node, group)
	if err != nil {
		return fmt.Errorf("change now node failed: %v", err)
	}
	return e.ChangeNode()
}

func (e *Entrance) GetNNodeAndNGroup() (node string, group string) {
	return e.nodeManager.GetNodes().NowNode.NName, e.nodeManager.GetNodes().NowNode.NGroup
}

func (e *Entrance) GetANodes() map[string][]string {
	m := map[string][]string{}

	for key := range e.nodeManager.GetNodes().Node {
		var x []string
		for node := range e.nodeManager.GetNodes().Node[key] {
			x = append(x, node)
		}
		sort.Strings(x)
		m[key] = x
	}
	return m
}

func (e *Entrance) GetOneNodeConn(group, nodeN string) (
	func(string) (net.Conn, error), func(string) (net.PacketConn, error), error) {
	if e.nodeManager.GetNodes().Node[group][nodeN] == nil {
		return nil, nil, fmt.Errorf("node %s of group %s is not exist", nodeN, group)
	}
	return subscr.ParseNodeConn(e.nodeManager.GetNodes().Node[group][nodeN])
}

func (e *Entrance) GetNodes(group string) ([]string, error) {
	var nodeTmp []string
	for nodeRemarks := range e.nodeManager.GetNodes().Node[group] {
		nodeTmp = append(nodeTmp, nodeRemarks)
	}
	sort.Strings(nodeTmp)
	return nodeTmp, nil
}

func (e *Entrance) GetGroups() ([]string, error) {
	var groupTmp []string
	for group := range e.nodeManager.GetNodes().Node {
		groupTmp = append(groupTmp, group)
	}
	sort.Strings(groupTmp)
	return groupTmp, nil
}

func (e *Entrance) UpdateSub() error {
	return e.nodeManager.GetLinkFromInt()
}

func (e *Entrance) GetLinks() (map[string]utils.Link, error) {
	return e.nodeManager.GetNodes().Links, nil
}

func (e *Entrance) AddLink(name, style, link string) error {
	return e.nodeManager.AddLink(name, style, link)
}

func (e *Entrance) DeleteNode(group, name string) error {
	return e.nodeManager.DeleteOneNode(group, name)
}

func (e *Entrance) DeleteLink(name string) error {
	return e.nodeManager.DeleteLink(name)
}

func (e *Entrance) ChangeNode() error {
	if e.nodeManager.GetNodes().NowNode == nil {
		return errors.New("NowNode is nil")
	}
	if e.nodeHash == e.nodeManager.GetNowNode().NHash {
		return nil
	}

	conn, packetConn, err := subscr.ParseNodeConn(e.nodeManager.GetNodes().NowNode)
	if err != nil {
		return fmt.Errorf("now node to conn failed: %v", err)
	}

	e.nodeHash = e.nodeManager.GetNowNode().NHash

	e.Bypass.SetProxy(conn, packetConn)

	return nil
}

func (e *Entrance) GetDownload() uint64 {
	return e.Bypass.GetDownload()
}

func (e *Entrance) GetUpload() uint64 {
	return e.Bypass.GetUpload()
}

func (e *Entrance) Latency(group, mark string) (time.Duration, error) {
	conn, _, err := e.GetOneNodeConn(group, mark)
	if err != nil {
		return 0, err
	}
	return latency.TcpLatency(
		func(_ context.Context, _, addr string) (net.Conn, error) {
			return conn(addr)
		},
		"https://www.google.com/generate_204",
	)
}
