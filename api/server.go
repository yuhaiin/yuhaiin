//+build api

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

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/controller"
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
)

type Server struct {
	UnimplementedApiServer
	singleInstanceCtx context.Context
	message           chan string
}

var (
	Host        string
	killWDC     bool // kill process when grpc disconnect
	initCtx     context.Context
	lockFileCtx context.Context
	connectCtx  context.Context
	connectDone context.CancelFunc
	signChannel chan os.Signal
)

func sigh() {
	signChannel = make(chan os.Signal)
	signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Println("kernel exit")
				_ = controller.LockFileClose()
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

	var cancel context.CancelFunc
	lockFileCtx, cancel = context.WithCancel(context.Background())
	err := controller.GetProcessLock(Host)
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
	cancel()

	fmt.Println("Create lock file successful.")
	fmt.Println("Try to initialize Service.")
	initCtx, cancel = context.WithCancel(context.Background())
	err = controller.Init()
	if err != nil {
		fmt.Println("Initialize Service failed, Exit Process!")
		panic(err)
	}
	fmt.Println("Initialize Service Successful, Please Connect in 5 Seconds.")
	cancel()

	connectCtx, connectDone = context.WithCancel(context.Background())
	go func(ctx context.Context) {
		select {
		case <-ctx.Done():
			fmt.Println("Connect Successful!")
		case <-time.After(5 * time.Second):
			log.Println("Connect timeout: 5 Seconds, Exit Process!")
			connectDone()
			os.Exit(0)
		}
	}(connectCtx)
}

func (s *Server) CreateLockFile(context.Context, *empty.Empty) (*empty.Empty, error) {
	if lockFileCtx == nil {
		return &empty.Empty{}, errors.New("create lock file false")
	}
	select {
	case <-lockFileCtx.Done():
		break
	default:
		return &empty.Empty{}, errors.New("create lock file false")
	}

	if initCtx == nil {
		return &empty.Empty{}, errors.New("init Process Failed")
	}
	select {
	case <-initCtx.Done():
		break
	default:
		return &empty.Empty{}, errors.New("init Process Failed")
	}

	if connectCtx != nil {
		select {
		case <-connectCtx.Done():
			return &empty.Empty{}, errors.New("already exists one client")
		default:
			connectDone()
		}
	}
	return &empty.Empty{}, nil
}

func (s *Server) ProcessInit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func (s *Server) GetRunningHost(context.Context, *empty.Empty) (*wrappers.StringValue, error) {
	host, err := controller.ReadLockFile()
	if err != nil {
		return &wrappers.StringValue{}, err
	}
	return &wrappers.StringValue{Value: host}, nil
}

func (s *Server) ClientOn(context.Context, *empty.Empty) (*empty.Empty, error) {
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

func (s *Server) ProcessExit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, controller.LockFileClose()
}

func (s *Server) GetConfig(context.Context, *empty.Empty) (*config.Setting, error) {
	conf, err := controller.GetConfig()
	return conf, err
}

func (s *Server) SetConfig(_ context.Context, req *config.Setting) (*empty.Empty, error) {
	return &empty.Empty{}, controller.SetConFig(req)
}

func (s *Server) ReimportRule(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, controller.MatchCon.UpdateMatch()
}

func (s *Server) GetGroup(context.Context, *empty.Empty) (*AllGroupOrNode, error) {
	groups, err := controller.GetGroups()
	return &AllGroupOrNode{Value: groups}, err
}

func (s *Server) GetNode(_ context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	nodes, err := controller.GetNodes(req.Value)
	return &AllGroupOrNode{Value: nodes}, err
}

func (s *Server) GetNowGroupAndName(context.Context, *empty.Empty) (*NowNodeGroupAndNode, error) {
	node, group := controller.GetNNodeAndNGroup()
	return &NowNodeGroupAndNode{Node: node, Group: group}, nil
}

func (s *Server) ChangeNowNode(_ context.Context, req *NowNodeGroupAndNode) (*empty.Empty, error) {
	return &empty.Empty{}, controller.ChangeNNode(req.Group, req.Node)
}

func (s *Server) UpdateSub(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, controller.UpdateSub()
}

func (s *Server) GetSubLinks(context.Context, *empty.Empty) (*AllGroupOrNode, error) {
	links, err := controller.GetLinks()
	return &AllGroupOrNode{Value: links}, err
}

func (s *Server) AddSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := controller.AddLink(req.Value)
	if err != nil {
		return nil, fmt.Errorf("api:AddSubLink -> %v", err)
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) DeleteSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := controller.DeleteLink(req.Value)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) Latency(_ context.Context, req *NowNodeGroupAndNode) (*wrappers.StringValue, error) {
	latency, err := controller.Latency(req.Group, req.Node)
	if err != nil {
		return nil, err
	}
	return &wrappers.StringValue{Value: latency.String()}, err
}

func (s *Server) GetRate(_ *empty.Empty, srv Api_GetRateServer) error {
	fmt.Println("Start Send Flow Message to Client.")
	da, ua := common.DownloadTotal, common.UploadTotal
	var dr string
	var ur string
	ctx := srv.Context()
	for {
		dr = common.ReducedUnitStr(float64(common.DownloadTotal-da)) + "/S"
		ur = common.ReducedUnitStr(float64(common.UploadTotal-ua)) + "/S"
		da, ua = common.DownloadTotal, common.UploadTotal

		err := srv.Send(&DaUaDrUr{
			Download: common.ReducedUnitStr(float64(da)),
			Upload:   common.ReducedUnitStr(float64(ua)),
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

func (s *Server) SingleInstance(srv Api_SingleInstanceServer) error {
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

func (s *Server) GetKernelPid(context.Context, *empty.Empty) (*wrappers.UInt32Value, error) {
	return &wrappers.UInt32Value{Value: uint32(os.Getpid())}, nil
}
