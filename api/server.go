package api

import (
	context "context"

	"github.com/Asutorufa/yuhaiin/subscr"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/golang/protobuf/ptypes/wrappers"

	"github.com/Asutorufa/yuhaiin/process/process"

	config "github.com/Asutorufa/yuhaiin/config"

	"github.com/golang/protobuf/ptypes/empty"
)

type Server struct {
	UnimplementedApiServer
}

func (s *Server) ProcessInit(context.Context, *empty.Empty) (*empty.Empty, error) {
	if err := config.PathInit(); err != nil {
		return &empty.Empty{}, err
	}
	return &empty.Empty{}, process.GetProcessLock()
}

func (s *Server) ProcessExit(ctx context.Context, req *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.LockFileClose()
}

func (s *Server) GetConfig(ctx context.Context, req *empty.Empty) (*config.Setting, error) {
	return process.GetConfig()
}

func (s *Server) SetConfig(ctx context.Context, req *config.Setting) (*empty.Empty, error) {
	return &empty.Empty{}, process.SetConFig(req, false)
}

func (s *Server) ReimportRule(ctx context.Context, req *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, process.MatchCon.UpdateMatch()
}

func (s *Server) GetGroup(ctx context.Context, req *empty.Empty) (*AllGroupOrNode, error) {
	groups, err := process.GetGroups()
	return &AllGroupOrNode{Value: groups}, err
}

func (s *Server) GetNode(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	nodes, err := process.GetNodes(req.Value)
	return &AllGroupOrNode{Value: nodes}, err
}

func (s *Server) GetNowGroupAndName(ctx context.Context, req *empty.Empty) (*NowNodeGroupAndNode, error) {
	node, group := process.GetNNodeAndNGroup()
	return &NowNodeGroupAndNode{Node: node, Group: group}, nil
}

func (s *Server) ChangeNowNode(ctx context.Context, req *NowNodeGroupAndNode) (*empty.Empty, error) {
	return &empty.Empty{}, process.ChangeNNode(req.Group, req.Node)
}

func (s *Server) UpdateSub(ctx context.Context, req *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, subscr.GetLinkFromInt()
}

func (s *Server) GetSubLinks(ctx context.Context, req *empty.Empty) (*AllGroupOrNode, error) {
	links, err := subscr.GetLink()
	return &AllGroupOrNode{Value: links}, err
}

func (s *Server) AddSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := subscr.AddLinkJSON(req.Value)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) DeleteSubLink(ctx context.Context, req *wrappers.StringValue) (*AllGroupOrNode, error) {
	err := subscr.RemoveLinkJSON(req.Value)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &empty.Empty{})
}

func (s *Server) Latency(ctx context.Context, req *NowNodeGroupAndNode) (*wrappers.StringValue, error) {
	latency, err := process.Latency(req.Group, req.Node)
	if err != nil {
		return nil, err
	}
	return &wrappers.StringValue{Value: latency.String()}, err
}

func (s *Server) GetAllDownAndUP(ctx context.Context, req *empty.Empty) (*DownAndUP, error) {
	dau := &DownAndUP{}
	dau.Download = common.DownloadTotal
	dau.Upload = common.UploadTotal
	return dau, nil
}

func (s *Server) ReducedUnit(ctx context.Context, req *wrappers.DoubleValue) (*wrappers.StringValue, error) {
	return &wrappers.StringValue{Value: common.ReducedUnitStr(req.Value)}, nil
}
