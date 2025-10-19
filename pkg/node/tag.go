package node

import (
	"context"
	"errors"
	"iter"
	"maps"

	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type tag struct {
	api.UnimplementedTagServer

	ruleTags func() iter.Seq[string]
	n        *Manager
}

func (t *tag) Save(_ context.Context, r *api.SaveTagReq) (*emptypb.Empty, error) {
	if r.GetType() == node.TagType_mirror && r.GetTag() == r.GetHash() {
		return &emptypb.Empty{}, errors.New("tag same as target mirror tag")
	}

	if _, ok := t.n.GetTag(r.GetTag()); ok {
		t.n.DeleteTag(r.GetTag())
	}

	t.n.AddTag(r.GetTag(), r.GetType(), r.GetHash())

	return &emptypb.Empty{}, t.n.Save()
}

func (t *tag) Remove(_ context.Context, r *wrapperspb.StringValue) (*emptypb.Empty, error) {
	t.n.DeleteTag(r.Value)
	return &emptypb.Empty{}, t.n.Save()
}

func (t *tag) List(ctx context.Context, _ *emptypb.Empty) (*api.TagsResponse, error) {
	resp := api.TagsResponse_builder{
		Tags: maps.Clone(t.n.GetTags()),
	}

	if t.ruleTags != nil {
		for v := range t.ruleTags() {
			if _, ok := resp.Tags[v]; !ok {
				resp.Tags[v] = &node.Tags{}
			}
		}
	}

	return resp.Build(), nil
}
