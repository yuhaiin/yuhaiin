package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/app"
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/utils"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
)

type Process struct {
	UnimplementedProcessInitServer

	singleInstance chan bool
	message        chan string
	m              *manager
}

func NewProcess() (*Process, error) {
	p := &Process{}
	p.m = newManager()
	err := p.m.Start()
	return p, err
}

func (s *Process) Host() string {
	return s.m.Host()
}

func (s *Process) CreateLockFile(context.Context, *empty.Empty) (*empty.Empty, error) {
	if !s.m.lockfile() {
		return &empty.Empty{}, errors.New("create lock file false")
	}

	if !s.m.initApp() {
		return &empty.Empty{}, errors.New("init Process Failed")
	}

	s.m.connect()
	return &empty.Empty{}, nil
}

func (s *Process) ProcessInit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func (s *Process) GetRunningHost(context.Context, *empty.Empty) (*wrappers.StringValue, error) {
	host, err := app.ReadLockFile()
	if err != nil {
		return &wrappers.StringValue{}, err
	}
	return &wrappers.StringValue{Value: host}, nil
}

func (s *Process) ClientOn(context.Context, *empty.Empty) (*empty.Empty, error) {
	if s.singleInstance != nil {
		select {
		case <-s.singleInstance:
			break
		default:
			s.message <- "on"
			return &empty.Empty{}, nil
		}
	}
	return &empty.Empty{}, errors.New("no client")
}

func (s *Process) ProcessExit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, app.LockFileClose()
}

func (s *Process) SingleInstance(srv ProcessInit_SingleInstanceServer) error {
	if s.singleInstance != nil {
		select {
		case <-s.singleInstance:
			break
		default:
			return errors.New("already exist one client")
		}
	}

	s.singleInstance = make(chan bool)
	s.message = make(chan string, 1)
	ctx := srv.Context()

	for {
		select {
		case m := <-s.message:
			err := srv.Send(&wrappers.StringValue{Value: m})
			if err != nil {
				log.Println(err)
			}
			fmt.Println("Call Client Open Window.")
		case <-ctx.Done():
			close(s.message)
			close(s.singleInstance)
			if s.m.killWDC {
				panic("client exit")
			}
			return ctx.Err()
		}
	}
}

func (s *Process) GetKernelPid(context.Context, *empty.Empty) (*wrappers.UInt32Value, error) {
	return &wrappers.UInt32Value{Value: uint32(os.Getpid())}, nil
}

func (s *Process) StopKernel(context.Context, *empty.Empty) (*empty.Empty, error) {
	defer os.Exit(0)
	return &empty.Empty{}, nil
}

type Config struct {
	UnimplementedConfigServer
}

func NewConfig() *Config {
	return &Config{}
}

func (c *Config) GetConfig(context.Context, *empty.Empty) (*config.Setting, error) {
	conf, err := app.GetConfig()
	return conf, err
}

func (c *Config) SetConfig(_ context.Context, req *config.Setting) (*empty.Empty, error) {
	return &empty.Empty{}, app.SetConFig(req)
}

func (c *Config) ReimportRule(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, app.RefreshMapping()
}

func (c *Config) GetRate(_ *empty.Empty, srv Config_GetRateServer) error {
	fmt.Println("Start Send Flow Message to Client.")
	//TODO deprecated string
	da, ua := app.GetDownload(), app.GetUpload()
	var dr string
	var ur string
	ctx := srv.Context()
	for {
		dr = utils.ReducedUnitStr(float64(app.GetDownload()-da)) + "/S"
		ur = utils.ReducedUnitStr(float64(app.GetUpload()-ua)) + "/S"
		da, ua = app.GetDownload(), app.GetUpload()

		err := srv.Send(&DaUaDrUr{
			Download: utils.ReducedUnitStr(float64(da)),
			Upload:   utils.ReducedUnitStr(float64(ua)),
			DownRate: dr,
			UpRate:   ur,
		})
		if err != nil {
			log.Println(err)
		}
		select {
		case <-ctx.Done():
			fmt.Println("Client is Hidden, Close Stream.")
			return ctx.Err()
		case <-time.After(time.Second):
			continue
		}
	}
}

type Node struct {
	UnimplementedNodeServer
}

func NewNode() *Node {
	return &Node{}
}

func (n *Node) GetNodes(context.Context, *empty.Empty) (*Nodes, error) {
	nodes := &Nodes{Value: map[string]*AllGroupOrNode{}}
	nods := app.GetANodes()
	for key := range nods {
		nodes.Value[key] = &AllGroupOrNode{Value: nods[key]}
	}
	return nodes, nil
}

func (n *Node) GetGroup(context.Context, *empty.Empty) (*AllGroupOrNode, error) {
	groups, err := app.GetGroups()
	return &AllGroupOrNode{Value: groups}, err
}

func (n *Node) GetNode(_ context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	nodes, err := app.GetNodes(req.Value)
	return &AllGroupOrNode{Value: nodes}, err
}

func (n *Node) GetNowGroupAndName(context.Context, *empty.Empty) (*GroupAndNode, error) {
	node, group := app.GetNNodeAndNGroup()
	return &GroupAndNode{Node: node, Group: group}, nil
}

func (n *Node) AddNode(_ context.Context, req *NodeMap) (*empty.Empty, error) {
	// TODO add node
	return &empty.Empty{}, nil
}

func (n *Node) ModifyNode(context.Context, *NodeMap) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func (n *Node) DeleteNode(_ context.Context, req *GroupAndNode) (*empty.Empty, error) {
	return &empty.Empty{}, app.DeleteNode(req.Group, req.Node)
}

func (n *Node) ChangeNowNode(_ context.Context, req *GroupAndNode) (*empty.Empty, error) {
	return &empty.Empty{}, app.ChangeNNode(req.Group, req.Node)
}

func (n *Node) Latency(_ context.Context, req *GroupAndNode) (*wrappers.StringValue, error) {
	latency, err := app.Latency(req.Group, req.Node)
	if err != nil {
		return nil, err
	}
	return &wrappers.StringValue{Value: latency.String()}, err
}

type Subscribe struct {
	UnimplementedSubscribeServer
}

func NewSubscribe() *Subscribe {
	return &Subscribe{}
}

func (s *Subscribe) UpdateSub(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, app.UpdateSub()
}

func (s *Subscribe) GetSubLinks(context.Context, *empty.Empty) (*Links, error) {
	links, err := app.GetLinks()
	if err != nil {
		return nil, err
	}
	l := &Links{}
	l.Value = map[string]*Link{}
	for key := range links {
		l.Value[key] = &Link{
			Type: links[key].Type,
			Url:  links[key].Url,
		}
	}
	return l, nil
}

func (s *Subscribe) AddSubLink(ctx context.Context, req *Link) (*Links, error) {
	err := app.AddLink(req.Name, req.Type, req.Url)
	if err != nil {
		return nil, fmt.Errorf("api:AddSubLink -> %v", err)
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Subscribe) DeleteSubLink(ctx context.Context, req *wrappers.StringValue) (*Links, error) {
	err := app.DeleteLink(req.Value)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}
