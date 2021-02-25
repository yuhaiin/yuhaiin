package api

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/app"
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/utils"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
)

var (
	Host    string
	killWDC bool // kill process when grpc disconnect

	initFinished     chan bool
	lockFileFinished chan bool
	connectFinished  chan bool
	signChannel      chan os.Signal
)

func sigh() {
	signChannel = make(chan os.Signal)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Println("kernel exit")
				_ = app.LockFileClose()
				os.Exit(0)
			default:
				fmt.Println("OTHERS SIGN:", s)
			}
		}
	}()
}

func init() {
	sigh()

	flag.StringVar(&Host, "host", "127.0.0.1:50051", "RPC SERVER HOST")
	flag.BoolVar(&killWDC, "kwdc", false, "kill process when grpc disconnect")
	flag.Parse()
	fmt.Println("gRPC Listen Host :", Host)
	fmt.Println("Try to create lock file.")

	lockFileFinished = make(chan bool)
	err := app.GetProcessLock(Host)
	if err != nil {
		fmt.Println("Create lock file failed, Please Get Running Host in 5 Seconds.")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		go func(ctx context.Context) {
			select {
			case <-ctx.Done():
				log.Println("Read Running Host timeout: 5 Seconds, Exit Process!")
				cancel()
				os.Exit(0)
			}
		}(ctx)
		return
	}
	close(lockFileFinished)

	fmt.Println("Create lock file successful.")
	fmt.Println("Try to initialize Service.")
	initFinished = make(chan bool)
	err = app.Init()
	if err != nil {
		fmt.Println("Initialize Service failed, Exit Process!")
		panic(err)
	}
	fmt.Println("Initialize Service Successful, Please Connect in 5 Seconds.")
	close(initFinished)

	connectFinished = make(chan bool)
	go func() {
		select {
		case <-connectFinished:
			fmt.Println("Connect Successful!")
		case <-time.After(5 * time.Second):
			log.Println("Connect timeout: 5 Seconds, Exit Process!")
			close(connectFinished)
			os.Exit(0)
		}
	}()
}

type Process struct {
	UnimplementedProcessInitServer
	singleInstanceCtx context.Context
	message           chan string
}

func (s *Process) CreateLockFile(context.Context, *empty.Empty) (*empty.Empty, error) {
	if lockFileFinished == nil {
		return &empty.Empty{}, errors.New("create lock file false")
	}
	select {
	case <-lockFileFinished:
		break
	default:
		return &empty.Empty{}, errors.New("create lock file false")
	}

	if initFinished == nil {
		return &empty.Empty{}, errors.New("init Process Failed")
	}
	select {
	case <-initFinished:
		break
	default:
		return &empty.Empty{}, errors.New("init Process Failed")
	}

	if connectFinished != nil {
		select {
		case <-connectFinished:
			return &empty.Empty{}, errors.New("already exists one client")
		default:
			close(connectFinished)
		}
	}
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
	if s.singleInstanceCtx != nil {
		select {
		case <-s.singleInstanceCtx.Done():
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
	if s.singleInstanceCtx != nil {
		select {
		case <-s.singleInstanceCtx.Done():
			break
		default:
			return errors.New("already exist one client")
		}
	}
	s.message = make(chan string, 1)
	s.singleInstanceCtx = srv.Context()

	for {
		select {
		case m := <-s.message:
			err := srv.Send(&wrappers.StringValue{Value: m})
			if err != nil {
				log.Println(err)
			}
			fmt.Println("Call Client Open Window.")
		case <-s.singleInstanceCtx.Done():
			close(s.message)
			if killWDC {
				panic("client exit")
			}
			return s.singleInstanceCtx.Err()
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

func (c *Config) GetConfig(context.Context, *empty.Empty) (*config.Setting, error) {
	conf, err := app.GetConfig()
	return conf, err
}

func (c *Config) SetConfig(_ context.Context, req *config.Setting) (*empty.Empty, error) {
	return &empty.Empty{}, app.SetConFig(req)
}

func (c *Config) ReimportRule(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, app.MatchCon.UpdateMatch()
}

func (c *Config) GetRate(_ *empty.Empty, srv Config_GetRateServer) error {
	fmt.Println("Start Send Flow Message to Client.")
	da, ua := utils.DownloadTotal, utils.UploadTotal
	var dr string
	var ur string
	ctx := srv.Context()
	for {
		dr = utils.ReducedUnitStr(float64(utils.DownloadTotal-da)) + "/S"
		ur = utils.ReducedUnitStr(float64(utils.UploadTotal-ua)) + "/S"
		da, ua = utils.DownloadTotal, utils.UploadTotal

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
	return &empty.Empty{}, app.AddNode(req.Value)
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
