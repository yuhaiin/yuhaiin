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

	netUtils "github.com/Asutorufa/yuhaiin/pkg/net/utils"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

type Entrance struct {
	config      *config.Config
	LocalListen *LocalListen
	Bypass      *BypassManager
	nodeManager *subscr.NodeManager
	shunt       *Shunt
	dir         string

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

	// initialize Match Controller
	if !e.config.GetSetting().Bypass.Enabled {
		e.Bypass, err = NewBypassManager(nil, getDNS(s.LocalDNS))
	} else {
		e.Bypass, err = NewBypassManager(e.shunt, getDNS(s.LocalDNS))
	}
	if err != nil {
		return nil, fmt.Errorf("create new bypass service failed: %v", err)
	}

	e.addObserver()
	return e, nil
}

func (e *Entrance) Start() (err error) {
	// initialize Local Servers Controller
	e.LocalListen, err = NewLocalListenCon(
		WithHTTP(e.config.GetSetting().Proxy.HTTP),
		WithSocks5(e.config.GetSetting().Proxy.Socks5),
		WithRedir(e.config.GetSetting().Proxy.Redir),
		WithProxy(e.Bypass),
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

			var err error
			if !current.Bypass.Enabled {
				e.Bypass, err = NewBypassManager(nil, getDNS(current.LocalDNS))
			} else {
				e.Bypass, err = NewBypassManager(e.shunt, getDNS(current.LocalDNS))
			}
			if err != nil {
				fmt.Printf("local listener apply config failed: %v", err)
			}
		}
	})

	e.config.AddObserver(func(current, _ *config.Setting) {
		err := e.LocalListen.SetAHost(
			WithHTTP(current.Proxy.HTTP),
			WithSocks5(current.Proxy.Socks5),
			WithRedir(current.Proxy.Redir),
		)
		if err != nil {
			fmt.Printf("local listener apply config failed: %v", err)
		}
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
	return e.config.GetSetting(), nil
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

func (e *Entrance) GetOneNodeConn(group, nodeN string) (netUtils.Proxy, error) {
	if e.nodeManager.GetNodes().Node[group][nodeN] == nil {
		return nil, fmt.Errorf("node %s of group %s is not exist", nodeN, group)
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

	p, err := subscr.ParseNodeConn(e.nodeManager.GetNodes().NowNode)
	if err != nil {
		return fmt.Errorf("now node to conn failed: %v", err)
	}

	e.nodeHash = e.nodeManager.GetNowNode().NHash

	e.Bypass.SetProxy(p)

	return nil
}

func (e *Entrance) GetDownload() uint64 {
	return e.Bypass.GetDownload()
}

func (e *Entrance) GetUpload() uint64 {
	return e.Bypass.GetUpload()
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
