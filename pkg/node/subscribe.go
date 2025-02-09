package node

import (
	"context"

	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Subscribe struct {
	gn.UnimplementedSubscribeServer

	n *Manager
}

func (f *Manager) Subscribe() *Subscribe {
	return &Subscribe{n: f}
}

func (s *Subscribe) Save(_ context.Context, l *gn.SaveLinkReq) (*emptypb.Empty, error) {
	s.n.Links().Save(l.GetLinks())
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Remove(_ context.Context, l *gn.LinkReq) (*emptypb.Empty, error) {
	s.n.Links().Delete(l.GetNames())
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Update(_ context.Context, req *gn.LinkReq) (*emptypb.Empty, error) {
	s.n.Links().Update(req.GetNames())
	return &emptypb.Empty{}, s.n.Save()
}

func (s *Subscribe) Get(context.Context, *emptypb.Empty) (*gn.GetLinksResp, error) {
	return gn.GetLinksResp_builder{Links: s.n.GetLinks()}.Build(), nil
}
