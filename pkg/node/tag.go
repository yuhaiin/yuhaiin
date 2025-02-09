package node

import (
	"context"
	"errors"
	"iter"
	"maps"

	gn "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type tag struct {
	gn.UnimplementedTagServer

	ruleTags func() iter.Seq[string]
	n        *Manager
}

func (f *Manager) Tag(ff func() iter.Seq[string]) gn.TagServer {
	return &tag{n: f, ruleTags: ff}
}

func (t *tag) Save(_ context.Context, r *gn.SaveTagReq) (*emptypb.Empty, error) {
	if r.GetType() == pt.TagType_mirror && r.GetTag() == r.GetHash() {
		return &emptypb.Empty{}, errors.New("tag same as target mirror tag")
	}

	if _, ok := t.n.ExistTag(r.GetTag()); ok {
		t.n.DeleteTag(r.GetTag())
	}

	t.n.AddTag(r.GetTag(), r.GetType(), r.GetHash())

	return &emptypb.Empty{}, t.n.Save()
}

func (t *tag) Remove(_ context.Context, r *wrapperspb.StringValue) (*emptypb.Empty, error) {
	t.n.DeleteTag(r.Value)
	return &emptypb.Empty{}, t.n.Save()
}

func (t *tag) List(ctx context.Context, _ *emptypb.Empty) (*gn.TagsResponse, error) {
	resp := gn.TagsResponse_builder{
		Tags: maps.Clone(t.n.GetTags()),
	}

	if t.ruleTags != nil {
		for v := range t.ruleTags() {
			if _, ok := resp.Tags[v]; !ok {
				resp.Tags[v] = &pt.Tags{}
			}
		}
	}

	return resp.Build(), nil
}

func (t *tag) bumpUsedNodes() []string {
	tags := t.n.GetTags()

	var nodes []string
	for _, v := range tags {
		if v.GetType() == pt.TagType_node {
			nodes = append(nodes, v.GetHash()...)
		}
	}

	return nodes
}
