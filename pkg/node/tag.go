package node

import (
	"context"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type tag struct {
	grpcnode.UnimplementedTagServer

	manager *manager
}

func NewTag(f *FileStore) grpcnode.TagServer { return &tag{manager: f.manAger} }

func (t *tag) Save(_ context.Context, r *grpcnode.SaveTagReq) (*emptypb.Empty, error) {
	if _, ok := t.manager.ExistTag(r.Tag); ok {
		t.manager.DeleteTag(r.Tag)
	}

	t.manager.AddTag(r.Tag, r.Hash)

	return &emptypb.Empty{}, nil
}

func (t *tag) Remove(_ context.Context, r *wrapperspb.StringValue) (*emptypb.Empty, error) {
	t.manager.DeleteTag(r.Value)
	return &emptypb.Empty{}, nil
}
