package inbound

import (
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/schema/api"
	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/paging"
)

type InboundCtr struct {
	db      chore.DB
	inbound *Inbound
}

func NewInboundCtr(s chore.DB, i *Inbound) *InboundCtr {
	_ = s.Batch(func(s *config.Setting) error {
		for name, v := range s.GetServer().GetInbounds() {
			if !v.GetEnabled() {
				continue
			}

			if v.GetName() != name {
				v.SetName(name)
			}

			i.Save(v)
		}

		i.SetHijackDnsFakeip(s.GetServer().GetHijackDnsFakeip())
		i.SetSniff(s.GetServer().GetSniff().GetEnabled())
		return nil
	})

	return &InboundCtr{db: s, inbound: i}
}

func (i *InboundCtr) List(ctx context.Context, req *api.Empty) (*api.InboundsResponse, error) {
	resp := &api.InboundsResponse{}

	err := i.db.View(func(s *config.Setting) error {
		inbounds := s.GetServer().GetInbounds()
		resp.SetNames(slices.Collect(maps.Keys(inbounds)))
		items := make([]*api.InboundItem, 0, len(inbounds))
		for name, inbound := range inbounds {
			items = append(items, inboundItem(name, inbound))
		}
		resp.SetItems(items)
		resp.SetHijackDns(s.GetServer().GetHijackDns())
		resp.SetHijackDnsFakeip(s.GetServer().GetHijackDnsFakeip())
		resp.SetSniff(s.GetServer().GetSniff())
		return nil
	})

	return resp, err
}

func inboundItem(name string, inbound *config.Inbound) *api.InboundItem {
	if inbound.GetName() != "" {
		name = inbound.GetName()
	}

	network := inbound.WhichNetwork().String()
	protocol := inbound.WhichProtocol().String()
	listen := ""

	switch inbound.WhichNetwork() {
	case config.Inbound_Tcpudp_case:
		listen = inbound.GetTcpudp().GetHost()
	case config.Inbound_Quic_case:
		listen = inbound.GetQuic().GetHost()
	}

	if listen == "" {
		switch inbound.WhichProtocol() {
		case config.Inbound_Redir_case:
			listen = inbound.GetRedir().GetHost()
		case config.Inbound_Tproxy_case:
			listen = inbound.GetTproxy().GetHost()
		case config.Inbound_Tun_case:
			listen = inbound.GetTun().GetPortal()
		}
	}

	transports := make([]string, 0, len(inbound.GetTransport()))
	for _, transport := range inbound.GetTransport() {
		if transport.WhichTransport() == config.Transport_Transport_not_set_case {
			continue
		}
		transports = append(transports, transport.WhichTransport().String())
	}

	return api.InboundItem_builder{
		Name:       new(name),
		Enabled:    new(inbound.GetEnabled()),
		Network:    new(network),
		Listen:     new(listen),
		Protocol:   new(protocol),
		Transports: transports,
	}.Build()
}

func (i *InboundCtr) ListPage(ctx context.Context, req *api.PageRequest) (*api.InboundsResponse, error) {
	resp, err := i.List(ctx, &api.Empty{})
	if err != nil {
		return resp, err
	}

	items := resp.GetItems()
	slices.SortFunc(items, func(a, b *api.InboundItem) int { return strings.Compare(a.GetName(), b.GetName()) })
	items = paging.Filter(items, req.GetQuery(), func(item *api.InboundItem, query string) bool {
		return paging.MatchString(item.GetName(), query) ||
			paging.MatchString(item.GetNetwork(), query) ||
			paging.MatchString(item.GetProtocol(), query) ||
			paging.MatchString(item.GetListen(), query)
	})
	pageItems, page, pageSize, total := paging.Slice(items, req.GetPage(), req.GetPageSize())
	pageNames := make([]string, 0, len(pageItems))
	for _, item := range pageItems {
		pageNames = append(pageNames, item.GetName())
	}
	resp.SetNames(pageNames)
	resp.SetItems(pageItems)
	resp.SetPage(api.PageResponse_builder{
		Page:     new(page),
		PageSize: new(pageSize),
		Total:    new(total),
	}.Build())
	return resp, nil
}

func (i *InboundCtr) Get(ctx context.Context, req *api.StringValue) (*config.Inbound, error) {
	resp := &config.Inbound{}
	err := i.db.View(func(s *config.Setting) error {
		var ok bool
		resp, ok = s.GetServer().GetInbounds()[req.Value]
		if !ok {
			return fmt.Errorf("inbound %s not found", req.Value)
		}

		return nil
	})

	return resp, err
}

func generateRealityKeys(v *config.Transport) error {
	if v.GetReality() == nil {
		return nil
	}

	if len(v.GetReality().GetPrivateKey()) != 0 {
		return nil
	}

	pri, pub, err := reality.GenerateKey()
	if err != nil {
		return err
	}
	v.GetReality().SetPrivateKey(pri)
	v.GetReality().SetPublicKey(pub)
	return nil
}

func generateTlsAuthCa(v *config.Transport) error {
	if v.GetTlsAuto() == nil {
		return nil
	}

	tlsAuth := v.GetTlsAuto()

	ech := tlsAuth.GetEch()
	if ech.GetEnable() {
		if ech.GetOuterSNI() == "" {
			ech.SetOuterSNI(rand.Text())
		}

		var id [1]byte
		_, _ = rand.Read(id[:])
		private, config, err := tls.NewECHConfig(id[0], []byte(ech.GetOuterSNI()))
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

func (i *InboundCtr) Save(ctx context.Context, req *config.Inbound) (*config.Inbound, error) {
	if req.GetName() == "" {
		return nil, fmt.Errorf("inbound name is empty")
	}

	for _, v := range req.GetTransport() {
		var err error
		switch v.WhichTransport() {
		case config.Transport_TlsAuto_case:
			err = generateTlsAuthCa(v)
		case config.Transport_Reality_case:
			err = generateRealityKeys(v)
		}
		if err != nil {
			return nil, err
		}
	}

	err := i.db.Batch(func(s *config.Setting) error {
		s.GetServer().GetInbounds()[req.GetName()] = req
		i.inbound.Save(req)
		return nil
	})
	return req, err
}

func (i *InboundCtr) Apply(ctx context.Context, req *api.InboundsResponse) (*api.Empty, error) {
	err := i.db.Batch(func(s *config.Setting) error {
		s.GetServer().SetHijackDns(req.GetHijackDns())
		s.GetServer().SetHijackDnsFakeip(req.GetHijackDnsFakeip())
		s.GetServer().SetSniff(req.GetSniff())

		i.inbound.SetHijackDnsFakeip(req.GetHijackDnsFakeip())
		i.inbound.SetSniff(req.GetSniff().GetEnabled())
		return nil
	})
	return &api.Empty{}, err
}

func (i *InboundCtr) Remove(ctx context.Context, req *api.StringValue) (*api.Empty, error) {
	err := i.db.Batch(func(s *config.Setting) error {
		delete(s.GetServer().GetInbounds(), req.Value)
		i.inbound.Remove(req.Value)
		return nil
	})
	return &api.Empty{}, err
}

var platformInfo []func(*api.PlatformInfoResponse)

func (i *InboundCtr) PlatformInfo(ctx context.Context, req *api.Empty) (*api.PlatformInfoResponse, error) {
	resp := &api.PlatformInfoResponse{}
	for _, v := range platformInfo {
		v(resp)
	}
	return resp, nil
}
