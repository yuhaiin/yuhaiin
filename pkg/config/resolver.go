package config

import (
	"context"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Resolver struct {
	s Setting
	gc.UnimplementedResolverServer
}

func NewResolver(s Setting) *Resolver {
	return &Resolver{s: s}
}

func (r *Resolver) List(ctx context.Context, req *emptypb.Empty) (*gc.ResolveList, error) {
	resp := &gc.ResolveList{}
	err := r.s.View(func(s *config.Setting) error {
		for k := range s.Dns.Resolver {
			resp.Names = append(resp.Names, k)
		}
		return nil
	})
	return resp, err
}

func (r *Resolver) Get(ctx context.Context, req *wrapperspb.StringValue) (*dns.Dns, error) {
	var dns *dns.Dns
	err := r.s.View(func(s *config.Setting) error {
		dns = s.Dns.Resolver[req.GetValue()]
		return nil
	})
	if err != nil {
		return nil, err
	}

	if dns == nil {
		return nil, fmt.Errorf("resolver [%s] is not exist", req.GetValue())
	}

	return dns, nil
}

func (r *Resolver) Save(ctx context.Context, req *gc.SaveResolver) (*dns.Dns, error) {
	err := r.s.Update(func(s *config.Setting) error {
		s.Dns.Resolver[req.Name] = req.Resolver
		return nil
	})
	return req.Resolver, err
}

func (r *Resolver) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := r.s.Update(func(s *config.Setting) error {
		delete(s.Dns.Resolver, req.Value)
		return nil
	})
	return &emptypb.Empty{}, err
}
