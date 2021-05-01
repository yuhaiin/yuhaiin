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
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

type Entrance struct {
	config      *config.Config
	localListen *Listener
	nodeManager *subscr.NodeManager
	shunt       *Shunt
	dir         string
	connManager *connManager

	nodeHash string
}

func NewEntrance(dir string) (e *Entrance, err error) {
	e = &Entrance{
		dir: dir,
	}

	e.config, err = config.NewConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("get config failed: %v", err)
	}

	e.nodeManager, err = subscr.NewNodeManager(filepath.Join(dir, "node.json"))
	if err != nil {
		return nil, fmt.Errorf("refresh node failed: %v", err)
	}

	s := e.config.GetSetting()

	e.shunt, err = NewShunt(s.Bypass.BypassFile, getDNS(s.DNS).LookupIP)
	if err != nil {
		return nil, fmt.Errorf("create shunt failed: %v", err)
	}

	e.connManager = newConnManager(e.getBypass())
	e.addObserver()
	return e, nil
}

func (e *Entrance) Start() (err error) {
	// initialize Local Servers Controller
	e.localListen, err = NewListener(e.config.GetSetting().GetProxy(), e.connManager)
	if err != nil {
		return fmt.Errorf("create local listener failed: %v", err)
	}
	return nil
}

func (e *Entrance) SetConFig(c *config.Setting) (err error) {
	err = e.config.Apply(c)
	if err != nil {
		return fmt.Errorf("apply config failed: %v", err)
	}
	return nil
}

func (e *Entrance) addObserver() {
	e.config.AddObserver(func(current, old *config.Setting) {
		if current.Bypass.BypassFile != old.Bypass.BypassFile {
			err := e.shunt.SetFile(current.Bypass.BypassFile)
			if err != nil {
				log.Printf("shunt set file failed: %v", err)
			}
		}
	})

	e.config.AddObserver(func(current, old *config.Setting) {
		if diffDNS(current.DNS, old.DNS) {
			e.shunt.SetLookup(getDNS(current.DNS).LookupIP)
		}
	})

	e.config.AddObserver(func(current, old *config.Setting) {
		if diffDNS(current.LocalDNS, old.LocalDNS) ||
			current.Bypass.Enabled != old.Bypass.Enabled {
			e.connManager.SetProxy(e.getBypass())
		}
	})

	e.config.AddObserver(func(current, _ *config.Setting) {
		e.localListen.SetServer(e.config.GetSetting().GetProxy())
	})
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
		return dns.NewDoH(dc.Host, toSubnet(dc.Subnet), nil)
	}
	return dns.NewDNS(dc.Host, toSubnet(dc.Subnet), nil)
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
	return e.config.GetSetting(), nil
}

func (e *Entrance) ChangeNNode(group string, node string) (err error) {
	err = e.nodeManager.ChangeNowNode(node, group)
	if err != nil {
		return fmt.Errorf("change now node failed: %v", err)
	}
	return e.changeNode()
}

func (e *Entrance) GetNNodeAndNGroup() (node string, group string) {
	if e.nodeManager.GetNodes().NowNode == nil {
		return "", ""
	}
	return e.nodeManager.GetNodes().NowNode.NName, e.nodeManager.GetNodes().NowNode.NGroup
}

func (e *Entrance) GetANodes() map[string][]string {
	m := map[string][]string{}

	for key := range e.nodeManager.GetNodes().Nodes {
		if e.nodeManager.GetNodes().Nodes[key] == nil {
			continue
		}
		var x []string
		for node := range e.nodeManager.GetNodes().Nodes[key].Node {
			x = append(x, node)
		}
		sort.Strings(x)
		m[key] = x
	}
	return m
}

func (e *Entrance) GetOneNodeConn(group, nodeN string) (proxy.Proxy, error) {
	if e.nodeManager.GetNodes().Nodes[group] == nil {
		return nil, fmt.Errorf("node %s of group %s is not exist", nodeN, group)
	}
	if e.nodeManager.GetNodes().Nodes[group].Node == nil {
		return nil, fmt.Errorf("node %s of group %s is not exist", nodeN, group)

	}
	return subscr.ParseNodeConn(e.nodeManager.GetNodes().Nodes[group].Node[nodeN])
}

func (e *Entrance) GetNodes(group string) ([]string, error) {
	if e.nodeManager.GetNodes().Nodes[group] == nil {
		return nil, nil
	}

	var nodeTmp []string
	for nodeRemarks := range e.nodeManager.GetNodes().Nodes[group].Node {
		nodeTmp = append(nodeTmp, nodeRemarks)
	}
	sort.Strings(nodeTmp)
	return nodeTmp, nil
}

func (e *Entrance) GetGroups() ([]string, error) {
	var groupTmp []string
	for group := range e.nodeManager.GetNodes().Nodes {
		groupTmp = append(groupTmp, group)
	}
	sort.Strings(groupTmp)
	return groupTmp, nil
}

func (e *Entrance) UpdateSub() error {
	return e.nodeManager.GetLinkFromInt()
}

func (e *Entrance) GetLinks() (map[string]*utils.NodeLink, error) {
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

func (e *Entrance) changeNode() error {
	if e.nodeManager.GetNodes().GetNowNode() == nil {
		return errors.New("NowNode is nil")
	}
	if e.nodeHash == e.nodeManager.GetNowNode().GetNHash() {
		return nil
	}
	e.nodeHash = e.nodeManager.GetNowNode().GetNHash()
	e.connManager.SetProxy(e.getBypass())
	return nil
}

func (e *Entrance) getNowNode() (p proxy.Proxy) {
	var err error
	p, err = subscr.ParseNodeConn(e.nodeManager.GetNodes().GetNowNode())
	if err != nil {
		log.Printf("now node to conn failed: %v", err)
		p = &proxy.DefaultProxy{}
	}

	return p
}

func (e *Entrance) getBypass() proxy.Proxy {
	if !e.config.GetSetting().Bypass.Enabled {
		return NewBypassManager(nil, getDNS(e.config.GetSetting().GetLocalDNS()), e.getNowNode())
	} else {
		return NewBypassManager(e.shunt, getDNS(e.config.GetSetting().GetLocalDNS()), e.getNowNode())
	}
}

func (e *Entrance) GetDownload() uint64 {
	return e.connManager.GetDownload()
}

func (e *Entrance) GetUpload() uint64 {
	return e.connManager.GetUpload()
}

func (e *Entrance) Latency(group, mark string) (time.Duration, error) {
	p, err := e.GetOneNodeConn(group, mark)
	if err != nil {
		return 0, err
	}
	return latency.TcpLatency(
		func(_ context.Context, _, addr string) (net.Conn, error) {
			return p.Conn(addr)
		},
		"https://www.google.com/generate_204",
	)
}
