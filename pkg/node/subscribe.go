package node

import (
	"context"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Subscribe struct {
	grpcnode.UnimplementedSubscribeServer

	fileStore *FileStore
}

func NewSubscribe(f *FileStore) *Subscribe {
	return &Subscribe{fileStore: f}
}

func (s *Subscribe) Save(_ context.Context, l *grpcnode.SaveLinkReq) (*emptypb.Empty, error) {
	s.fileStore.link().Save(l.GetLinks())
	return &emptypb.Empty{}, s.fileStore.Save()
}

func (s *Subscribe) Remove(_ context.Context, l *grpcnode.LinkReq) (*emptypb.Empty, error) {
	s.fileStore.link().Delete(l.GetNames())
	return &emptypb.Empty{}, s.fileStore.Save()
}

func (s *Subscribe) Update(_ context.Context, req *grpcnode.LinkReq) (*emptypb.Empty, error) {
	s.fileStore.link().Update(req.Names)
	return &emptypb.Empty{}, s.fileStore.Save()
}

func (s *Subscribe) Get(context.Context, *emptypb.Empty) (*grpcnode.GetLinksResp, error) {
	return &grpcnode.GetLinksResp{Links: s.fileStore.link().Links()}, nil
}
