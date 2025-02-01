package config

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/log"
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
		names = slices.Collect(maps.Keys(s.GetServer().GetInbounds()))
		return nil
	})

	return gc.InboundsResponse_builder{Names: names}.Build(), err
}

func (i *Inbound) Get(ctx context.Context, req *wrapperspb.StringValue) (*listener.Inbound, error) {
	resp := &listener.Inbound{}
	err := i.s.View(func(s *config.Setting) error {
		var ok bool
		resp, ok = s.GetServer().GetInbounds()[req.Value]
		if !ok {
			return fmt.Errorf("inbound %s not found", req.Value)
		}

		return nil
	})

	return resp, err
}

func generateTlsAuthCa(v *listener.Transport) error {
	if v.GetTlsAuto() == nil {
		return nil
	}

	tlsAuth := v.GetTlsAuto()

	if len(tlsAuth.GetCaCert()) != 0 && len(tlsAuth.GetCaKey()) != 0 {
		_, err := cert.ParseCa(tlsAuth.GetCaCert(), tlsAuth.GetCaKey())
		if err != nil {
			return fmt.Errorf("parse ca failed: %w", err)
		}
		return nil
	}

	log.Info("tls ca cert or key is empty, regenerate new ca")

	ca, err := cert.GenerateCa()
	if err != nil {
		return err
	}

	cert, err := ca.CertBytes()
	if err != nil {
		return err
	}

	key, err := ca.PrivateKeyBytes()
	if err != nil {
		return err
	}

	tlsAuth.SetCaCert(cert)
	tlsAuth.SetCaKey(key)

	return nil
}

func (i *Inbound) Save(ctx context.Context, req *listener.Inbound) (*listener.Inbound, error) {
	if req.GetName() == "" {
		return nil, fmt.Errorf("inbound name is empty")
	}

	for _, v := range req.GetTransport() {
		err := generateTlsAuthCa(v)
		if err != nil {
			return nil, err
		}
	}

	err := i.s.Batch(func(s *config.Setting) error {
		s.GetServer().GetInbounds()[req.GetName()] = req
		return nil
	})
	return req, err
}

func (i *Inbound) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := i.s.Batch(func(s *config.Setting) error {
		delete(s.GetServer().GetInbounds(), req.Value)
		return nil
	})
	return &emptypb.Empty{}, err
}
