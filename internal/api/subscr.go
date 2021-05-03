package api

import (
	"context"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var _ SubscribeServer = (*Subscribe)(nil)

type Subscribe struct {
	UnimplementedSubscribeServer
	nodeManager subscr.NodeManagerServer
}

func NewSubscribe(e subscr.NodeManagerServer) SubscribeServer {
	return &Subscribe{nodeManager: e}
}

func (s *Subscribe) UpdateSub(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return s.nodeManager.RefreshSubscr(context.TODO(), &emptypb.Empty{})
}

func (s *Subscribe) GetSubLinks(context.Context, *emptypb.Empty) (*Links, error) {
	z, err := s.nodeManager.GetNodes(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return nil, fmt.Errorf("get nodes failed: %v", err)
	}

	l := &Links{Value: make(map[string]*Link)}

	for key := range z.Links {
		l.Value[key] = &Link{
			Type: z.Links[key].Type,
			Url:  z.Links[key].Url,
		}
	}
	return l, nil
}

func (s *Subscribe) AddSubLink(ctx context.Context, req *Link) (*Links, error) {
	_, err := s.nodeManager.AddLink(
		context.TODO(),
		&subscr.NodeLink{
			Name: req.Name,
			Url:  req.Url,
			Type: req.Type,
		},
	)
	if err != nil {
		return &Links{}, fmt.Errorf("add link failed: %v", err)
	}
	return s.GetSubLinks(ctx, &emptypb.Empty{})
}

func (s *Subscribe) DeleteSubLink(ctx context.Context, req *wrapperspb.StringValue) (*Links, error) {
	_, err := s.nodeManager.DeleteLink(context.TODO(), req)
	if err != nil {
		return nil, err
	}
	return s.GetSubLinks(ctx, &emptypb.Empty{})
}
