package node

import (
	"context"

	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Subscribe struct {
	gn.UnimplementedSubscribeServer

	n *Nodes
}

func (f *Nodes) Subscribe() *Subscribe {
	return &Subscribe{n: f}
}

func (s *Subscribe) Save(_ context.Context, l *gn.SaveLinkReq) (*emptypb.Empty, error) {
	s.n.links.Save(l.GetLinks())
	return &emptypb.Empty{}, s.n.db.Save()
}

func (s *Subscribe) Remove(_ context.Context, l *gn.LinkReq) (*emptypb.Empty, error) {
	s.n.links.Delete(l.GetNames())
	return &emptypb.Empty{}, s.n.db.Save()
}

func (s *Subscribe) Update(_ context.Context, req *gn.LinkReq) (*emptypb.Empty, error) {
	s.n.links.Update(req.Names)
	return &emptypb.Empty{}, s.n.db.Save()
}

func (s *Subscribe) Get(context.Context, *emptypb.Empty) (*gn.GetLinksResp, error) {
	return &gn.GetLinksResp{Links: s.n.links.Links()}, nil
}
