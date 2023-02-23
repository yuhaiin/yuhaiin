package node

import (
	"context"

	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Subscribe struct {
	gn.UnimplementedSubscribeServer

	fileStore *FileStore
}

func NewSubscribe(f *FileStore) *Subscribe {
	return &Subscribe{fileStore: f}
}

func (s *Subscribe) Save(_ context.Context, l *gn.SaveLinkReq) (*emptypb.Empty, error) {
	s.fileStore.link().Save(l.GetLinks())
	return &emptypb.Empty{}, s.fileStore.Save()
}

func (s *Subscribe) Remove(_ context.Context, l *gn.LinkReq) (*emptypb.Empty, error) {
	s.fileStore.link().Delete(l.GetNames())
	return &emptypb.Empty{}, s.fileStore.Save()
}

func (s *Subscribe) Update(_ context.Context, req *gn.LinkReq) (*emptypb.Empty, error) {
	s.fileStore.link().Update(req.Names)
	return &emptypb.Empty{}, s.fileStore.Save()
}

func (s *Subscribe) Get(context.Context, *emptypb.Empty) (*gn.GetLinksResp, error) {
	return &gn.GetLinksResp{Links: s.fileStore.link().Links()}, nil
}
