package config

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Inbound struct {
	s Setting
	gc.UnimplementedInboundServer
}

func NewInbound(s Setting) *Inbound {
	return &Inbound{s: s}
}

func (i *Inbound) List(ctx context.Context, req *emptypb.Empty) (*gc.InboundsResponse, error) {
	names := []string{}
	err := i.s.View(func(s *config.Setting) error {
		names = slices.Collect(maps.Keys(s.Server.Inbounds))
		return nil
	})

	return &gc.InboundsResponse{Names: names}, err
}

func (i *Inbound) Get(ctx context.Context, req *wrapperspb.StringValue) (*listener.Inbound, error) {
	resp := &listener.Inbound{}
	err := i.s.View(func(s *config.Setting) error {
		var ok bool
		resp, ok = s.Server.Inbounds[req.Value]
		if !ok {
			return fmt.Errorf("inbound %s not found", req.Value)
		}

		return nil
	})

	return resp, err
}

func (i *Inbound) Save(ctx context.Context, req *listener.Inbound) (*listener.Inbound, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("inbound name is empty")
	}

	err := i.s.Update(func(s *config.Setting) error {
		s.Server.Inbounds[req.Name] = req
		return nil
	})
	return req, err
}

func (i *Inbound) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := i.s.Update(func(s *config.Setting) error {
		delete(s.Server.Inbounds, req.Value)
		return nil
	})
	return &emptypb.Empty{}, err
}
