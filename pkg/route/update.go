package route

import (
	"context"
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
				r, err := getRemote(filepath.Join(path, "rules"), s, hostname, force)
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

func (s *Route) apply(path string, c *bypass.Config, force bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.updateCustomRule(path, c, force)
	s.updateRules(path, c, force)
	s.config = c
}

type RuleController struct {
	gc.UnimplementedBypassServer
	mu    sync.RWMutex
	route *Route
	db    config.DB
}

func NewRuleController(db config.DB, r *Route) *RuleController {
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
	defer s.mu.RUnlock()

	return s.route.config, nil
}

func (s *RuleController) Save(ctx context.Context, config *bypass.Config) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.route.apply(s.db.Dir(), config, false)

	err := s.db.Batch(func(s *pc.Setting) error {
		s.SetBypass(config)
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
