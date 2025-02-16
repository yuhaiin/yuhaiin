package inbound

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	cf "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type InboundCtr struct {
	db      pc.DB
	inbound *Inbound
	gc.UnimplementedInboundServer
}

// NewInboundCtr
// TODO hijackDNS,sniff switch
func NewInboundCtr(s pc.DB, i *Inbound) *InboundCtr {
	_ = s.View(func(s *pc.Setting) error {
		for _, v := range s.GetServer().GetInbounds() {
			if !v.GetEnabled() {
				continue
			}
			i.Save(v)
		}

		i.SetHijackDnsFakeip(s.GetServer().GetHijackDnsFakeip())
		i.SetSniff(s.GetServer().GetSniff().GetEnabled())
		return nil
	})

	return &InboundCtr{db: s, inbound: i}
}

func (i *InboundCtr) List(ctx context.Context, req *emptypb.Empty) (*gc.InboundsResponse, error) {
	resp := &gc.InboundsResponse{}

	err := i.db.View(func(s *pc.Setting) error {
		resp.SetNames(slices.Collect(maps.Keys(s.GetServer().GetInbounds())))
		resp.SetHijackDns(s.GetServer().GetHijackDns())
		resp.SetHijackDnsFakeip(s.GetServer().GetHijackDnsFakeip())
		resp.SetSniff(s.GetServer().GetSniff())
		return nil
	})

	return resp, err
}

func (i *InboundCtr) Get(ctx context.Context, req *wrapperspb.StringValue) (*cf.Inbound, error) {
	resp := &cf.Inbound{}
	err := i.db.View(func(s *pc.Setting) error {
		var ok bool
		resp, ok = s.GetServer().GetInbounds()[req.Value]
		if !ok {
			return fmt.Errorf("inbound %s not found", req.Value)
		}

		return nil
	})

	return resp, err
}

func generateTlsAuthCa(v *cf.Transport) error {
	if v.GetTlsAuto() == nil {
		return nil
	}

	tlsAuth := v.GetTlsAuto()

	ech := tlsAuth.GetEch()
	if ech.GetEnable() {
		if ech.GetOuterSNI() == "" {
			var buf [16]byte
			_, _ = rand.Read(buf[:])
			ech.SetOuterSNI(hex.EncodeToString(buf[:]))
		}

		var id [1]byte
		_, _ = rand.Read(id[:])
		private, config, err := tls.NewConfig(id[0], []byte(ech.GetOuterSNI()))
		if err != nil {
			return err
		}

		ech.SetConfig(config)
		ech.SetPrivateKey(private.Bytes())
	}

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

func (i *InboundCtr) Save(ctx context.Context, req *cf.Inbound) (*cf.Inbound, error) {
	if req.GetName() == "" {
		return nil, fmt.Errorf("inbound name is empty")
	}

	for _, v := range req.GetTransport() {
		err := generateTlsAuthCa(v)
		if err != nil {
			return nil, err
		}
	}

	err := i.db.Batch(func(s *pc.Setting) error {
		s.GetServer().GetInbounds()[req.GetName()] = req
		i.inbound.Save(req)
		return nil
	})
	return req, err
}

func (i *InboundCtr) Apply(ctx context.Context, req *gc.InboundsResponse) (*emptypb.Empty, error) {
	err := i.db.Batch(func(s *pc.Setting) error {
		s.GetServer().SetHijackDns(req.GetHijackDns())
		s.GetServer().SetHijackDnsFakeip(req.GetHijackDnsFakeip())
		s.GetServer().SetSniff(req.GetSniff())

		i.inbound.SetHijackDnsFakeip(req.GetHijackDnsFakeip())
		i.inbound.SetSniff(req.GetSniff().GetEnabled())
		return nil
	})
	return &emptypb.Empty{}, err
}

func (i *InboundCtr) Remove(ctx context.Context, req *wrapperspb.StringValue) (*emptypb.Empty, error) {
	err := i.db.Batch(func(s *pc.Setting) error {
		delete(s.GetServer().GetInbounds(), req.Value)
		i.inbound.Remove(req.Value)
		return nil
	})
	return &emptypb.Empty{}, err
}
