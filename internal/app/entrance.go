package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	hash, err := e.nodeManager.GetHash(group, node)
	if err != nil {
		return fmt.Errorf("get hash failed: %v", err)
	}
	log.Println(hash)
	p, err := e.nodeManager.ChangeNowNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return fmt.Errorf("change now node failed: %v", err)
	}
	log.Println(p)
	return e.changeNode()
}

func (e *Entrance) GetNNodeAndNGroup() (node string, group string) {
	p, err := e.nodeManager.Now(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return "", ""
	}
	return p.NName, p.NGroup
}

func (e *Entrance) GetANodes() map[string][]string {
	m := map[string][]string{}

	n, err := e.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		log.Println(err)
		return m
	}

	for k, v := range n.GroupNodesMap {
		sort.Strings(v.Nodes)
		m[k] = v.Nodes
	}

	return m
}

func (e *Entrance) GetOneNodeConn(group, nodeN string) (proxy.Proxy, error) {
	hash, err := e.nodeManager.GetHash(group, nodeN)
	if err != nil {
		return nil, fmt.Errorf("get hash failed: %v", err)
	}

	p, err := e.nodeManager.GetNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		return nil, fmt.Errorf("get node failed: %v", err)
	}

	return subscr.ParseNodeConn(p)
}

func (e *Entrance) GetNodes(group string) ([]string, error) {
	n, err := e.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return nil, fmt.Errorf("get nodes failed: %v", err)
	}

	g, ok := n.GroupNodesMap[group]
	if !ok {
		return nil, fmt.Errorf("group %v is not exist", group)
	}

	return g.Nodes, nil
}

func (e *Entrance) GetGroups() ([]string, error) {
	z, err := e.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return nil, fmt.Errorf("get nodes failed: %v", err)
	}
	return z.Groups, nil
}

func (e *Entrance) UpdateSub() error {
	_, err := e.nodeManager.RefreshSubscr(context.TODO(), &emptypb.Empty{})
	return err
}

func (e *Entrance) GetLinks() (map[string]*subscr.NodeLink, error) {
	z, err := e.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return nil, fmt.Errorf("get nodes failed: %v", err)
	}
	return z.Links, nil
}

func (e *Entrance) AddLink(name, style, link string) error {
	_, err := e.nodeManager.AddLink(
		context.TODO(),
		&subscr.NodeLink{
			Name: name,
			Url:  link,
		},
	)
	return err
}

func (e *Entrance) DeleteNode(group, name string) error {
	hash, err := e.nodeManager.GetHash(group, name)
	if err != nil {
		return nil
	}
	_, err = e.nodeManager.DeleteNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
	return err
}

func (e *Entrance) DeleteLink(name string) error {
	_, err := e.nodeManager.DeleteLink(context.TODO(), &wrapperspb.StringValue{Value: name})
	return err
}

func (e *Entrance) changeNode() error {
	n, err := e.nodeManager.Now(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("get now node failed: %v", err)
	}
	if e.nodeHash == n.GetNHash() {
		return nil
	}
	e.nodeHash = n.GetNHash()
	e.connManager.SetProxy(e.getBypass())
	return nil
}

func (e *Entrance) getNowNode() (p proxy.Proxy) {
	n, err := e.nodeManager.Now(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return &proxy.DefaultProxy{}
	}

	p, err = subscr.ParseNodeConn(n)
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

func (e *Entrance) Latency(group, mark string) (*wrapperspb.StringValue, error) {
	hash, err := e.nodeManager.GetHash(group, mark)
	if err != nil {
		return &wrapperspb.StringValue{Value: err.Error()}, err
	}
	return e.nodeManager.Latency(context.TODO(), &wrapperspb.StringValue{Value: hash})
}
