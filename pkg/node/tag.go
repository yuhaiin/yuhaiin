package node

import (
	"context"
	"errors"
	"maps"

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
	if r.GetType() == pt.TagType_mirror && r.GetTag() == r.GetHash() {
		return &emptypb.Empty{}, errors.New("tag same as target mirror tag")
	}

	if _, ok := t.n.manager.ExistTag(r.GetTag()); ok {
		t.n.manager.DeleteTag(r.GetTag())
	}

	t.n.manager.AddTag(r.GetTag(), r.GetType(), r.GetHash())

	return &emptypb.Empty{}, t.n.db.Save()
}

func (t *tag) Remove(_ context.Context, r *wrapperspb.StringValue) (*emptypb.Empty, error) {
	t.n.manager.DeleteTag(r.Value)
	return &emptypb.Empty{}, t.n.db.Save()
}

func (t *tag) List(ctx context.Context, _ *emptypb.Empty) (*gn.TagsResponse, error) {
	resp := gn.TagsResponse_builder{
		Tags: maps.Clone(t.n.manager.GetTags()),
	}

	if t.n.ruleTags != nil {
		for v := range t.n.ruleTags() {
			if _, ok := resp.Tags[v]; !ok {
				resp.Tags[v] = &pt.Tags{}
			}
		}
	}

	return resp.Build(), nil
}
