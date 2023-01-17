package node

import (
	"context"
	"errors"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type tag struct {
	grpcnode.UnimplementedTagServer

	manager   *manager
	fileStore *FileStore
}

func NewTag(f *FileStore) grpcnode.TagServer { return &tag{manager: f.manAger, fileStore: f} }

func (t *tag) Save(_ context.Context, r *grpcnode.SaveTagReq) (*emptypb.Empty, error) {
	if r.Type == pt.Type_mirror && r.Tag == r.Hash {
		return &emptypb.Empty{}, errors.New("tag same as target mirror tag")
	}

	if _, ok := t.manager.ExistTag(r.Tag); ok {
		t.manager.DeleteTag(r.Tag)
	}

	t.manager.AddTag(r.Tag, r.Type, r.Hash)

	return &emptypb.Empty{}, t.fileStore.Save()
}

func (t *tag) Remove(_ context.Context, r *wrapperspb.StringValue) (*emptypb.Empty, error) {
	t.manager.DeleteTag(r.Value)
	return &emptypb.Empty{}, t.fileStore.Save()
}
