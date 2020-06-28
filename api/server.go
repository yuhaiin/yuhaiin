package api

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/Asutorufa/yuhaiin/process/process"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
)

type Server struct {
	UnimplementedApiServer
}

var (
	message   chan string
	messageOn bool
)

func (s *Server) ProcessInit(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.GetProcessLock()
}

func (s *Server) ClientOn(ctx context.Context, req *empty.Empty) (*empty.Empty, error) {
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
	return process.GetConfig()
}

func (s *Server) SetConfig(_ context.Context, req *config.Setting) (*empty.Empty, error) {
	return &empty.Empty{}, process.SetConFig(req, false)
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
		case <-ctx.Done():
			close(message)
			messageOn = false
			return ctx.Err()
		}
	}
}
