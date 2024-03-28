package node

import (
	"context"
	"errors"

	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type tag struct {
	gn.UnimplementedTagServer

	n *Nodes
}

func (f *Nodes) Tag() gn.TagServer { return &tag{n: f} }

func (t *tag) Save(_ context.Context, r *gn.SaveTagReq) (*emptypb.Empty, error) {
	if r.Type == pt.TagType_mirror && r.Tag == r.Hash {
		return &emptypb.Empty{}, errors.New("tag same as target mirror tag")
	}

	if _, ok := t.n.manager.ExistTag(r.Tag); ok {
		t.n.manager.DeleteTag(r.Tag)
	}

	t.n.manager.AddTag(r.Tag, r.Type, r.Hash)

	return &emptypb.Empty{}, t.n.db.Save()
}

func (t *tag) Remove(_ context.Context, r *wrapperspb.StringValue) (*emptypb.Empty, error) {
	t.n.manager.DeleteTag(r.Value)
	return &emptypb.Empty{}, t.n.db.Save()
}
