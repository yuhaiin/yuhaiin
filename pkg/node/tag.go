package node

import (
	"context"
	"errors"
	"iter"
	"maps"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/paging"
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
		if err := t.n.DeleteTag(r.GetTag()); err != nil {
			return &emptypb.Empty{}, err
		}
	}

	return &emptypb.Empty{}, t.n.AddTag(r.GetTag(), r.GetType(), r.GetHash())
}

func (t *tag) Remove(_ context.Context, r *wrapperspb.StringValue) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, t.n.DeleteTag(r.Value)
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

func (t *tag) ListPage(ctx context.Context, req *api.TagPageRequest) (*api.TagsResponse, error) {
	resp, err := t.List(ctx, &emptypb.Empty{})
	if err != nil {
		return resp, err
	}

	names := slices.Collect(maps.Keys(resp.GetTags()))
	slices.Sort(names)
	names = paging.Filter(names, req.GetQuery(), paging.MatchString)
	pageNames, page, pageSize, total := paging.Slice(names, req.GetPage(), req.GetPageSize())

	items := make([]*api.TagItem, 0, len(pageNames))
	pageTags := make(map[string]*node.Tags, len(pageNames))
	for _, name := range pageNames {
		tag := resp.GetTags()[name]
		pageTags[name] = tag
		items = append(items, api.TagItem_builder{
			Name: new(name),
			Tag:  tag,
		}.Build())
	}

	resp.SetTags(pageTags)
	resp.SetItems(items)
	resp.SetPage(api.TagPage_builder{
		Page:     new(page),
		PageSize: new(pageSize),
		Total:    new(total),
	}.Build())
	return resp, nil
}
