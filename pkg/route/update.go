package route

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Deprecated: use [Rules] instead
func (s *Route) updateCustomRule(path string, c *bypass.Config, force bool) {
	if !force && slices.EqualFunc(
		s.config.GetCustomRuleV3(),
		c.GetCustomRuleV3(),
		func(mc1, mc2 *bypass.ModeConfig) bool { return proto.Equal(mc1, mc2) },
	) {
		return
	}

	trie := newRouteTires()

	for _, v := range c.GetCustomRuleV3() {
		v.SetErrorMsgs(make(map[string]string))

		mark := v.ToModeEnum()

		for _, hostname := range v.GetHostname() {
			scheme := getScheme(hostname)

			switch scheme.Scheme() {
			case "http", "https":
				r, err := getRemote(context.TODO(), filepath.Join(path, "rules"), s, hostname, force)
				if err != nil {
					v.GetErrorMsgs()[hostname] = err.Error()
					log.Error("get remote failed", "err", err, "url", hostname)
					continue
				}

				for v := range slice.RangeReaderByLine(r) {
					scheme := getScheme(v)

					trie.insert(scheme, mark)
				}
			default:
				trie.insert(scheme, mark)
			}
		}
	}

	s.customTrie.Store(trie)
}

// Deprecated: use [Rules] instead
func (s *Route) updateRules(path string, c *bypass.Config, force bool) {
	if !force && slices.EqualFunc(
		s.config.GetRemoteRules(),
		c.GetRemoteRules(),
		func(mc1, mc2 *bypass.RemoteRule) bool { return proto.Equal(mc1, mc2) },
	) {
		return
	}

	s.trie.Store(parseTrie(filepath.Join(path, "rules"), s, c.GetRemoteRules(), force))
}

// Deprecated: use [Rules] instead
func (s *Route) apply(path string, c *bypass.Config, force bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.updateCustomRule(path, c, force)
	s.updateRules(path, c, force)

	s.config = c
}

// Deprecated: use [Rules] instead
type RuleController struct {
	gc.UnimplementedBypassServer
	db    config.DB
	route *Route
	mu    sync.RWMutex
}

// Deprecated: use [Rules] instead
func NewRuleController(db config.DB, r *Route) *RuleController {
	// migrate old config
	{
		lists := map[string]*bypass.List{}
		rules := []*bypass.Rulev2{}

		err := db.Batch(func(s *pc.Setting) error {
			if len(s.GetBypass().GetRulesV2()) > 0 || len(s.GetBypass().GetLists()) > 0 || len(s.GetBypass().GetCustomRuleV3()) == 0 {
				return nil
			}

			for index, rule := range s.GetBypass().GetCustomRuleV3() {
				namePrefix := ""
				if rule.GetTag() == "" {
					namePrefix = fmt.Sprintf("%s_%d", rule.GetMode().String(), index)
				} else {
					namePrefix = fmt.Sprintf("%s_%d", rule.GetTag(), index)
				}

				listNames := map[string]bool{}

				for _, hostname := range rule.GetHostname() {
					data := getScheme(hostname)
					switch data.Scheme() {
					default:
						name := fmt.Sprintf("%s_host", namePrefix)
						listNames[name] = false

						list := lists[name]
						if list == nil || list.GetLocal() == nil {
							list = bypass.List_builder{
								ListType: bypass.List_host.Enum(),
								Name:     proto.String(name),
								Local:    &bypass.ListLocal{},
							}.Build()
							lists[name] = list
						}

						list.GetLocal().SetLists(append(list.GetLocal().GetLists(), data.Data()))

					case "process":
						name := fmt.Sprintf("%s_process", namePrefix)
						listNames[name] = true

						list := lists[name]
						if list == nil || list.GetLocal() == nil {
							list = bypass.List_builder{
								ListType: bypass.List_process.Enum(),
								Name:     proto.String(name),
								Local:    &bypass.ListLocal{},
							}.Build()
							lists[name] = list
						}

						list.GetLocal().SetLists(append(list.GetLocal().GetLists(), data.Data()))
					case "file", "http", "https":
						name := fmt.Sprintf("%s_remote", namePrefix)
						listNames[name] = false

						list := lists[name]
						if list == nil || list.GetRemote() == nil {
							list = bypass.List_builder{
								ListType: bypass.List_host.Enum(),
								Name:     proto.String(name),
								Remote:   &bypass.ListRemote{},
							}.Build()
							lists[name] = list
						}

						list.GetRemote().SetUrls(append(list.GetRemote().GetUrls(), data.Data()))
					}
				}

				or := []*bypass.Or{}
				for name, process := range listNames {
					if process {
						or = append(or, bypass.Or_builder{
							Rules: []*bypass.Rule{
								bypass.Rule_builder{
									Process: bypass.Process_builder{
										List: proto.String(name),
									}.Build(),
								}.Build(),
							},
						}.Build())
					} else {
						or = append(or, bypass.Or_builder{
							Rules: []*bypass.Rule{
								bypass.Rule_builder{
									Host: bypass.Host_builder{
										List: proto.String(name),
									}.Build(),
								}.Build(),
							},
						}.Build())
					}
				}

				rules = append(rules, bypass.Rulev2_builder{
					Name:                 proto.String(namePrefix),
					Mode:                 rule.GetMode().Enum(),
					Tag:                  proto.String(rule.GetTag()),
					ResolveStrategy:      rule.GetResolveStrategy().Enum(),
					UdpProxyFqdnStrategy: rule.GetUdpProxyFqdnStrategy().Enum(),
					Resolver:             proto.String(rule.GetResolver()),
					Rules:                or,
				}.Build())
			}

			s.GetBypass().SetLists(lists)
			s.GetBypass().SetRulesV2(rules)

			return nil
		})
		if err != nil {
			log.Error("migrate old config failed", "err", err)
		}
	}

	go func() {
		// make it run in background, so it won't block the main thread
		_ = db.Batch(func(s *pc.Setting) error {
			r.apply(db.Dir(), s.GetBypass(), false)
			return nil
		})
	}()

	return &RuleController{
		route: r,
		db:    db,
	}
}

func (s *RuleController) Load(ctx context.Context, empty *emptypb.Empty) (*bypass.Config, error) {
	s.mu.RLock()
	config := proto.CloneOf(s.route.config)
	s.mu.RUnlock()

	config.SetLists(nil)
	config.SetRulesV2(nil)

	return config, nil
}

func (s *RuleController) Save(ctx context.Context, config *bypass.Config) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.route.apply(s.db.Dir(), config, false)

	err := s.db.Batch(func(s *pc.Setting) error {
		s.GetBypass().SetEnabledV2(config.GetEnabledV2())
		s.GetBypass().SetCustomRuleV3(config.GetCustomRuleV3())
		s.GetBypass().SetRemoteRules(config.GetRemoteRules())
		s.GetBypass().SetBypassFile(config.GetBypassFile())
		s.GetBypass().SetUdpProxyFqdn(config.GetUdpProxyFqdn())
		s.GetBypass().SetResolveLocally(config.GetResolveLocally())
		s.GetBypass().SetDirectResolver(config.GetDirectResolver())
		s.GetBypass().SetProxyResolver(config.GetProxyResolver())
		s.GetBypass().SetTcp(config.GetTcp())
		s.GetBypass().SetUdp(config.GetUdp())
		return nil
	})

	return &emptypb.Empty{}, err
}

func (s *RuleController) Reload(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var config *bypass.Config

	_ = s.db.Batch(func(s *pc.Setting) error {
		config = s.GetBypass()
		return nil
	})

	s.route.apply(s.db.Dir(), config, true)

	return &emptypb.Empty{}, nil
}

func (s *RuleController) Test(ctx context.Context, req *wrapperspb.StringValue) (*gc.TestResponse, error) {
	addr := netapi.ParseAddressPort("", req.GetValue(), 0)
	host, portstr, err := net.SplitHostPort(req.GetValue())
	if err == nil {
		port, err := strconv.ParseUint(portstr, 10, 16)
		if err == nil {
			addr = netapi.ParseAddressPort(host, host, uint16(port))
		}
	}

	store := netapi.GetContext(ctx)

	result := s.route.dispatch(store, bypass.Mode_bypass, addr)

	return (&gc.TestResponse_builder{
		Mode: (&bypass.ModeConfig_builder{
			Mode:            result.Mode.Mode().Enum(),
			Tag:             proto.String(result.Mode.GetTag()),
			ResolveStrategy: result.Mode.GetResolveStrategy().Enum(),
		}).Build(),
		AfterAddr: proto.String(result.Addr.String()),
		Reason:    proto.String(result.Reason),
	}).Build(), nil
}

func (s *RuleController) BlockHistory(context.Context, *emptypb.Empty) (*gc.BlockHistoryList, error) {
	return s.route.RejectHistory.Get(), nil
}
