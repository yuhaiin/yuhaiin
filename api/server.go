//+build api

package api

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/process"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
)

type Server struct {
	UnimplementedApiServer
}

var (
	message     chan string
	messageOn   bool
	InitSuccess bool
	Host        string
)

func init() {
	flag.StringVar(&Host, "host", "127.0.0.1:50051", "RPC SERVER HOST")
	flag.Parse()
	fmt.Println("gRPC Listen Host :", Host)
	fmt.Println("Try to create lock file.")
	err := process.GetProcessLock(Host)
	if err != nil {
		fmt.Println("Create lock file failed, Please Get Running Host in 5 Seconds.")
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		go func(ctx context.Context) {
			select {
			case <-ctx.Done():
				log.Println("Read Running Host timeout: 5 Seconds, Exit Process!")
				os.Exit(0)
			}
		}(ctx)
		return
	}
	fmt.Println("Create lock file successful.")
	fmt.Println("Try to initialize Service.")
	err = process.Init()
	if err != nil {
		fmt.Println("Initialize Service failed, Exit Process!")
		panic(err)
	}
	fmt.Println("Initialize Service Successful.")
	InitSuccess = true
}

func (s *Server) CreateLockFile(context.Context, *empty.Empty) (*empty.Empty, error) {
	if !InitSuccess {
		return &empty.Empty{}, errors.New("create lock file false")
	}
	return &empty.Empty{}, nil
}

func (s *Server) ProcessInit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func (s *Server) GetRunningHost(context.Context, *empty.Empty) (*wrappers.StringValue, error) {
	host, err := process.ReadLockFile()
	if err != nil {
		return &wrappers.StringValue{}, err
	}
	return &wrappers.StringValue{Value: host}, nil
}

func (s *Server) ClientOn(context.Context, *empty.Empty) (*empty.Empty, error) {
	if !messageOn {
		return &empty.Empty{}, errors.New("no client")
	}
	message <- "on"
	return &empty.Empty{}, nil
}

func (s *Server) ProcessExit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.LockFileClose()
}

func (s *Server) GetConfig(context.Context, *empty.Empty) (*config.Setting, error) {
	conf, err := process.GetConfig()
	return conf, err
}

func (s *Server) SetConfig(_ context.Context, req *config.Setting) (*empty.Empty, error) {
	return &empty.Empty{}, process.SetConFig(req)
}

func (s *Server) ReimportRule(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.MatchCon.UpdateMatch()
}

func (s *Server) GetGroup(context.Context, *empty.Empty) (*AllGroupOrNode, error) {
	groups, err := process.GetGroups()
	return &AllGroupOrNode{Value: groups}, err
}

func (s *Server) GetNode(_ context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	nodes, err := process.GetNodes(req.Value)
	return &AllGroupOrNode{Value: nodes}, err
}

func (s *Server) GetNowGroupAndName(context.Context, *empty.Empty) (*NowNodeGroupAndNode, error) {
	node, group := process.GetNNodeAndNGroup()
	return &NowNodeGroupAndNode{Node: node, Group: group}, nil
}

func (s *Server) ChangeNowNode(_ context.Context, req *NowNodeGroupAndNode) (*empty.Empty, error) {
	return &empty.Empty{}, process.ChangeNNode(req.Group, req.Node)
}

func (s *Server) UpdateSub(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.UpdateSub()
}

func (s *Server) GetSubLinks(context.Context, *empty.Empty) (*AllGroupOrNode, error) {
	links, err := process.GetLinks()
	return &AllGroupOrNode{Value: links}, err
}

func (s *Server) AddSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := process.AddLink(req.Value)
	if err != nil {
		return nil, fmt.Errorf("api:AddSubLink -> %v", err)
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) DeleteSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := process.DeleteLink(req.Value)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) Latency(_ context.Context, req *NowNodeGroupAndNode) (*wrappers.StringValue, error) {
	latency, err := process.Latency(req.Group, req.Node)
	if err != nil {
		return nil, err
	}
	return &wrappers.StringValue{Value: latency.String()}, err
}

func (s *Server) GetAllDownAndUP(context.Context, *empty.Empty) (*DownAndUP, error) {
	dau := &DownAndUP{}
	dau.Download = common.DownloadTotal
	dau.Upload = common.UploadTotal
	return dau, nil
}

func (s *Server) ReducedUnit(_ context.Context, req *wrappers.DoubleValue) (*wrappers.StringValue, error) {
	return &wrappers.StringValue{Value: common.ReducedUnitStr(req.Value)}, nil
}

func (s *Server) SingleInstance(srv Api_SingleInstanceServer) error {
	if messageOn {
		return errors.New("already exist one client")
	}
	message = make(chan string, 1)
	messageOn = true
	ctx := srv.Context()

	for {
		select {
		case m := <-message:
			err := srv.Send(&wrappers.StringValue{Value: m})
			if err != nil {
				log.Println(err)
			}
			fmt.Println("Call Client Open Main Window.")
		case <-ctx.Done():
			close(message)
			messageOn = false
			return ctx.Err()
		}
	}
}
