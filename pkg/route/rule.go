package route

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Args struct {
	Tag                  string
	Mode                 config.Mode
	ResolveStrategy      config.ResolveStrategy
	UdpProxyFqdnStrategy config.UdpProxyFqdnStrategy
}

// ParseArgs parse args
// args: tag=tag,udp_proxy_fqdn,resolve_strategy=prefer_ipv6
func ParseArgs(mode config.Mode, fs RawArgs) Args {
	f := Args{Mode: mode}

	for key, value := range fs.Range {
		switch key {
		case "tag":
			f.Tag = value
		case "resolve_strategy":
			f.ResolveStrategy = config.ResolveStrategy(config.ResolveStrategy_value[value])
		case "udp_proxy_fqdn":
			if value == "true" {
				f.UdpProxyFqdnStrategy = config.UdpProxyFqdnStrategy_skip_resolve
			} else {
				f.UdpProxyFqdnStrategy = config.UdpProxyFqdnStrategy_resolve
			}
		}
	}

	return f
}

func (a Args) ToModeConfig(hostname []string) *config.ModeConfig {
	return (&config.ModeConfig_builder{
		Mode:                 a.Mode.Enum(),
		Tag:                  proto.String(a.Tag),
		Hostname:             hostname,
		ResolveStrategy:      a.ResolveStrategy.Enum(),
		UdpProxyFqdnStrategy: a.UdpProxyFqdnStrategy.Enum(),
	}).Build()
}

func TrimComment(s string) string {
	if i := strings.IndexByte(s, '#'); i != -1 {
		return s[:i]
	}

	return s
}

func SplitHostArgs(s string) (uri *Uri, args string, ok bool) {
	if len(s) == 0 {
		return
	}

	if s[0] == '"' || s[0] == '\'' {
		i := strings.IndexByte(s[1:], s[0])
		if i == -1 {
			return
		}

		uri = getScheme(s[1 : i+1])
		args = strings.TrimSpace(s[i+2:])
		ok = true
	} else {
		i := strings.IndexByte(s, ' ')
		if i == -1 {
			return
		}

		uri = getScheme(s[:i])
		args = strings.TrimSpace(s[i+1:])
		ok = true
	}

	return
}

func SplitModeArgs(s string) (x unique.Handle[config.ModeEnum], ok bool) {
	fs := strings.FieldsFunc(s, func(r rune) bool { return r == ',' })
	if len(fs) < 1 {
		return
	}

	modestr := strings.ToLower(fs[0])

	mode := config.Mode(config.Mode_value[modestr])

	if mode.Unknown() {
		mode = config.Mode_proxy
	}

	return ParseArgs(mode, fs[1:]).ToModeConfig(nil).ToModeEnum(), true
}

type RawArgs []string

func (a RawArgs) Range(f func(k, v string) bool) {
	for i := range a {
		x := a[i]

		var k, v string
		i := strings.IndexByte(x, '=')
		if i == -1 {
			k = x
			v = "true"
		} else {
			k = x[:i]
			v = x[i+1:]
		}

		if !f(strings.ToLower(k), strings.ToLower(v)) {
			return
		}
	}
}

func getScheme(h string) *Uri {
	h = TrimComment(h)

	u, err := url.Parse(h)
	if err != nil {
		u = &url.URL{
			Scheme: "default",
			Host:   h,
		}
	}
	switch u.Scheme {
	case "file", "process", "http", "https":
	default:
		u = &url.URL{
			Scheme: "default",
			Host:   h,
		}
	}

	return &Uri{u}
}

type routeTries struct {
	trie        *trie.Trie[unique.Handle[config.ModeEnum]]
	processTrie *domain.Fqdn[unique.Handle[config.ModeEnum]]
	tagsMap     map[string]struct{}
}

func newRouteTires() *routeTries {
	r := &routeTries{
		trie:        trie.NewTrie[unique.Handle[config.ModeEnum]](),
		processTrie: domain.NewDomainMapper[unique.Handle[config.ModeEnum]](),
		tagsMap:     make(map[string]struct{}),
	}

	r.processTrie.SetSeparate(filepath.Separator)

	return r
}

func (s *routeTries) insert(uri *Uri, mode unique.Handle[config.ModeEnum]) {
	if tag := mode.Value().GetTag(); tag != "" {
		s.tagsMap[strings.ToLower(tag)] = struct{}{}
	}

	switch uri.Scheme() {
	case "file":
		path := uri.Data()
		for x := range slice.RangeFileByLine(path) {
			uri := getScheme(x)
			if uri.Scheme() == "file" && !filepath.IsAbs(uri.Data()) {
				uri.SetData(filepath.Join(filepath.Dir(path), uri.Data()))
			}

			s.insert(uri, mode)
		}

	case "process":
		s.processTrie.Insert(convertVolumeName(uri.Data()), mode)
	default:
		if uri.Data() == "" {
			return
		}

		s.trie.Insert(strings.ToLower(uri.Data()), mode)
	}
}

type Uri struct {
	uri *url.URL
}

func (u *Uri) Scheme() string {
	return u.uri.Scheme
}

func (u *Uri) Data() string {
	switch u.uri.Scheme {
	case "file":
		return filepath.Join(u.uri.Host, u.uri.Path)
	case "http", "https":
		return u.uri.String()
	case "process":
		if u.uri.Opaque != "" {
			return u.uri.Opaque
		}

		return filepath.Join(u.uri.Host, u.uri.Path)
	}

	if u.uri.Host != "" {
		return u.uri.Host
	}

	return u.uri.Path
}

func (u *Uri) SetData(str string) {
	switch u.uri.Scheme {
	case "file":
		u.uri.Host = ""
		u.uri.Path = str
	case "http", "https":
		nu, err := url.Parse(str)
		if err == nil {
			u.uri = nu
		}
	case "process":
		u.uri.Opaque = str
		u.uri.Path = ""
		u.uri.Host = ""
	default:
		u.uri.Host = str
		u.uri.Path = ""
	}
}

func (u *Uri) String() string {
	return u.Scheme() + "://" + u.Data()
}

type Rules struct {
	db    chore.DB
	route *Route
	api.UnimplementedRulesServer
}

func NewRules(db chore.DB, route *Route) *Rules {
	_ = db.View(func(s *config.Setting) error {
		route.ms.Update(s.GetBypass().GetRulesV2())
		return nil
	})

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
	err := r.db.Batch(func(ss *config.Setting) error {
		if req.GetIndex() == nil {
			ss.GetBypass().SetRulesV2(append(ss.GetBypass().GetRulesV2(), req.GetRule()))
			r.route.ms.Add(req.GetRule())
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

		r.route.ms.Update(ss.GetBypass().GetRulesV2())
		return nil
	})

	return &emptypb.Empty{}, err
}

func (r *Rules) Remove(ctx context.Context, index *api.RuleIndex) (*emptypb.Empty, error) {
	err := r.db.Batch(func(s *config.Setting) error {
		if err := r.checkIndex(s, index); err != nil {
			return err
		}

		s.GetBypass().SetRulesV2(slices.Delete(s.GetBypass().GetRulesV2(), int(index.GetIndex()), int(index.GetIndex())+1))

		r.route.ms.Update(s.GetBypass().GetRulesV2())
		return nil
	})

	return &emptypb.Empty{}, err
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

	result := r.route.dispatch(ctx, addr)

	return api.TestResponse_builder{
		Mode: config.ModeConfig_builder{
			Mode:            result.Mode.Mode().Enum(),
			Tag:             proto.String(result.Mode.GetTag()),
			ResolveStrategy: result.Mode.GetResolveStrategy().Enum(),
		}.Build(),
		AfterAddr:   proto.String(result.Addr.String()),
		MatchResult: netapi.GetContext(ctx).MatchHistory(),
	}.Build(), nil
}

func (r *Rules) BlockHistory(context.Context, *emptypb.Empty) (*api.BlockHistoryList, error) {
	return r.route.Get(), nil
}
