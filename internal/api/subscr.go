package api

import (
	"context"
	"fmt"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Subscribe struct {
	UnimplementedSubscribeServer
	entrance *app.Entrance
}

func NewSubscribe(e *app.Entrance) *Subscribe {
	return &Subscribe{
		entrance: e,
	}
}

func (s *Subscribe) UpdateSub(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.entrance.UpdateSub()
}

func (s *Subscribe) GetSubLinks(context.Context, *emptypb.Empty) (*Links, error) {
	links, err := s.entrance.GetLinks()
	if err != nil {
		return nil, err
	}
	l := &Links{}
	l.Value = map[string]*Link{}
	for key := range links {
		l.Value[key] = &Link{
			Type: links[key].Type,
			Url:  links[key].Url,
		}
	}
	return l, nil
}

func (s *Subscribe) AddSubLink(ctx context.Context, req *Link) (*Links, error) {
	err := s.entrance.AddLink(req.Name, req.Type, req.Url)
	if err != nil {
		return nil, fmt.Errorf("api:AddSubLink -> %v", err)
	}
	return s.GetSubLinks(ctx, &emptypb.Empty{})
}

func (s *Subscribe) DeleteSubLink(ctx context.Context, req *wrapperspb.StringValue) (*Links, error) {
	err := s.entrance.DeleteLink(req.Value)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &emptypb.Empty{})
}
