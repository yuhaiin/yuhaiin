package route

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Rules struct {
	api.UnimplementedRulesServer
	db    chore.DB
	route *Route
}

func NewRules(db chore.DB, route *Route) *Rules {
	var rules []*config.Rulev2
	_ = db.View(func(s *config.Setting) error {
		rules = s.GetBypass().GetRulesV2()
		return nil
	})
	if rules != nil {
		route.ms.Update(rules...)
	}

	r := &Rules{
		db:    db,
		route: route,
	}

	cfg, err := r.Config(context.TODO(), &emptypb.Empty{})
	if err != nil {
		log.Warn("get rules config error", "err", err)
	} else {
		r.route.config.Store(cfg)
	}

	return r
}

func (r *Rules) List(ctx context.Context, empty *emptypb.Empty) (*api.RuleResponse, error) {
	names := make([]string, 0)
	err := r.db.View(func(ss *config.Setting) error {
		for _, v := range ss.GetBypass().GetRulesV2() {
			names = append(names, v.GetName())
		}
		return nil
	})

	return api.RuleResponse_builder{
		Names: names,
	}.Build(), err
}

func (r *Rules) Get(ctx context.Context, index *api.RuleIndex) (*config.Rulev2, error) {
	var resp *config.Rulev2
	err := r.db.View(func(ss *config.Setting) error {
		if err := r.checkIndex(ss, index); err != nil {
			return err
		}

		resp = ss.GetBypass().GetRulesV2()[index.GetIndex()]

		return nil
	})

	return resp, err
}

func (r *Rules) Save(ctx context.Context, req *api.RuleSaveRequest) (*emptypb.Empty, error) {
	var rules []*config.Rulev2
	var add bool
	err := r.db.Batch(func(ss *config.Setting) error {
		if req.GetIndex() == nil {
			ss.GetBypass().SetRulesV2(append(ss.GetBypass().GetRulesV2(), req.GetRule()))
			rules = []*config.Rulev2{req.GetRule()}
			add = true
			return nil
		}

		if req.GetIndex().GetIndex() >= uint32(len(ss.GetBypass().GetRulesV2())) {
			return fmt.Errorf("can't find rule %d", req.GetIndex().GetIndex())
		}

		rule := ss.GetBypass().GetRulesV2()[req.GetIndex().GetIndex()]

		if rule.GetName() != req.GetRule().GetName() {
			return fmt.Errorf("rule name not match, get: %s, want: %s", rule.GetName(), req.GetRule().GetName())
		}

		ss.GetBypass().GetRulesV2()[req.GetIndex().GetIndex()] = req.GetRule()

		rules = ss.GetBypass().GetRulesV2()
		return nil
	})
	if err != nil {
		return &emptypb.Empty{}, err
	}

	if add {
		r.route.ms.Add(rules...)
	} else {
		r.route.ms.Update(rules...)
	}

	return &emptypb.Empty{}, nil
}

func (r *Rules) Remove(ctx context.Context, index *api.RuleIndex) (*emptypb.Empty, error) {
	var rules []*config.Rulev2
	err := r.db.Batch(func(s *config.Setting) error {
		if err := r.checkIndex(s, index); err != nil {
			return err
		}

		s.GetBypass().SetRulesV2(slices.Delete(s.GetBypass().GetRulesV2(), int(index.GetIndex()), int(index.GetIndex())+1))

		rules = s.GetBypass().GetRulesV2()
		return nil
	})
	if err != nil {
		return &emptypb.Empty{}, err
	}

	r.route.ms.Update(rules...)

	return &emptypb.Empty{}, nil
}

func (r *Rules) ChangePriority(ctx context.Context, req *api.ChangePriorityRequest) (*emptypb.Empty, error) {
	err := r.db.Batch(func(s *config.Setting) error {
		if err := r.checkIndex(s, req.GetSource()); err != nil {
			return fmt.Errorf("source index error: %w", err)
		}

		if err := r.checkIndex(s, req.GetTarget()); err != nil {
			return fmt.Errorf("target index error: %w", err)
		}

		switch req.GetOperate() {
		case api.ChangePriorityRequest_Exchange:
			src := s.GetBypass().GetRulesV2()[req.GetSource().GetIndex()]
			tar := s.GetBypass().GetRulesV2()[req.GetTarget().GetIndex()]

			s.GetBypass().GetRulesV2()[req.GetSource().GetIndex()] = tar
			s.GetBypass().GetRulesV2()[req.GetTarget().GetIndex()] = src

		case api.ChangePriorityRequest_InsertBefore:
			result := InsertBefore(s.GetBypass().GetRulesV2(),
				int(req.GetSource().GetIndex()), int(req.GetTarget().GetIndex()))

			s.GetBypass().SetRulesV2(result)
		case api.ChangePriorityRequest_InsertAfter:
			result := InsertAfter(s.GetBypass().GetRulesV2(),
				int(req.GetSource().GetIndex()), int(req.GetTarget().GetIndex()))

			s.GetBypass().SetRulesV2(result)
		default:
			return fmt.Errorf("unknown operate: %d", req.GetOperate())
		}

		r.route.ms.ChangePriority(int(req.GetSource().GetIndex()),
			int(req.GetTarget().GetIndex()), req.GetOperate())
		return nil
	})

	return &emptypb.Empty{}, err
}

func InsertBefore[T any](s []T, from, to int) []T {
	result := make([]T, 0, len(s))

	elem := s[from]

	for index, v := range s {
		if index == from {
			continue
		}

		if index == to {
			result = append(result, elem)
		}

		result = append(result, v)
	}

	return result
}

func InsertAfter[T any](s []T, from, to int) []T {
	result := make([]T, 0, len(s))

	elem := s[from]

	for index, v := range s {
		if index == from {
			continue
		}

		result = append(result, v)

		if index == to {
			result = append(result, elem)
		}
	}

	return result
}

func (r *Rules) checkIndex(s *config.Setting, index *api.RuleIndex) error {
	if len(s.GetBypass().GetRulesV2())-1 < int(index.GetIndex()) {
		return fmt.Errorf("can't find rule %d", index.GetIndex())
	}

	rule := s.GetBypass().GetRulesV2()[index.GetIndex()]

	if rule.GetName() != index.GetName() {
		return fmt.Errorf("rule name not match, get: %s, want: %s", rule.GetName(), index.GetName())
	}

	return nil
}

func (r *Rules) Config(context.Context, *emptypb.Empty) (*config.Configv2, error) {
	var resp *config.Configv2
	err := r.db.View(func(ss *config.Setting) error {
		resp = config.Configv2_builder{
			DirectResolver: proto.String(ss.GetBypass().GetDirectResolver()),
			ProxyResolver:  proto.String(ss.GetBypass().GetProxyResolver()),
			ResolveLocally: proto.Bool(ss.GetBypass().GetResolveLocally()),
			UdpProxyFqdn:   ss.GetBypass().GetUdpProxyFqdn().Enum(),
		}.Build()

		return nil
	})

	return resp, err
}

func (r *Rules) SaveConfig(ctx context.Context, req *config.Configv2) (*emptypb.Empty, error) {
	err := r.db.Batch(func(setting *config.Setting) error {
		if !setting.HasBypass() {
			setting.SetBypass(&config.BypassConfig{})
		}

		setting.GetBypass().SetDirectResolver(req.GetDirectResolver())
		setting.GetBypass().SetProxyResolver(req.GetProxyResolver())
		setting.GetBypass().SetResolveLocally(req.GetResolveLocally())
		setting.GetBypass().SetUdpProxyFqdn(req.GetUdpProxyFqdn())

		r.route.config.Store(req)
		return nil
	})

	return &emptypb.Empty{}, err
}

func (r *Rules) Test(ctx context.Context, req *wrapperspb.StringValue) (*api.TestResponse, error) {
	var addr netapi.Address
	host, portstr, err := net.SplitHostPort(req.GetValue())
	if err == nil {
		port, er := strconv.ParseUint(portstr, 10, 16)
		if er != nil {
			return nil, fmt.Errorf("parse port failed: %w", er)
		}
		addr, err = netapi.ParseAddressPort(host, host, uint16(port))
	} else {
		addr, err = netapi.ParseAddressPort("", req.GetValue(), 0)
	}
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	s := netapi.GetContext(ctx)
	result := r.route.dispatch(s, addr)

	ips, _ := s.ConnOptions().RouteIPs(s, addr)

	return api.TestResponse_builder{
		Mode: config.ModeConfig_builder{
			Mode:            result.Mode.Mode().Enum(),
			Tag:             proto.String(result.Mode.GetTag()),
			ResolveStrategy: result.Mode.GetResolveStrategy().Enum(),
		}.Build(),
		AfterAddr:   proto.String(result.Addr.String()),
		MatchResult: netapi.GetContext(ctx).MatchHistory(),
		Lists:       s.ConnOptions().Lists(),
		Ips: func() []string {
			var ret []string
			for ip := range ips.Iter() {
				ret = append(ret, ip.String())
			}
			return ret
		}(),
	}.Build(), nil
}

func (r *Rules) BlockHistory(context.Context, *emptypb.Empty) (*api.BlockHistoryList, error) {
	return r.route.Get(), nil
}
