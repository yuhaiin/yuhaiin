package route

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Args struct {
	Tag                  string
	Mode                 bypass.Mode
	ResolveStrategy      bypass.ResolveStrategy
	UdpProxyFqdnStrategy bypass.UdpProxyFqdnStrategy
}

// ParseArgs parse args
// args: tag=tag,udp_proxy_fqdn,resolve_strategy=prefer_ipv6
func ParseArgs(mode bypass.Mode, fs RawArgs) Args {
	f := Args{Mode: mode}

	for key, value := range fs.Range {
		switch key {
		case "tag":
			f.Tag = value
		case "resolve_strategy":
			f.ResolveStrategy = bypass.ResolveStrategy(bypass.ResolveStrategy_value[value])
		case "udp_proxy_fqdn":
			if value == "true" {
				f.UdpProxyFqdnStrategy = bypass.UdpProxyFqdnStrategy_skip_resolve
			} else {
				f.UdpProxyFqdnStrategy = bypass.UdpProxyFqdnStrategy_resolve
			}
		}
	}

	return f
}

func (a Args) ToModeConfig(hostname []string) *bypass.ModeConfig {
	return (&bypass.ModeConfig_builder{
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

func SplitModeArgs(s string) (x unique.Handle[bypass.ModeEnum], ok bool) {
	fs := strings.FieldsFunc(s, func(r rune) bool { return r == ',' })
	if len(fs) < 1 {
		return
	}

	modestr := strings.ToLower(fs[0])

	mode := bypass.Mode(bypass.Mode_value[modestr])

	if mode.Unknown() {
		mode = bypass.Mode_proxy
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
	trie        *trie.Trie[unique.Handle[bypass.ModeEnum]]
	processTrie *domain.Fqdn[unique.Handle[bypass.ModeEnum]]
	tagsMap     map[string]struct{}
}

func newRouteTires() *routeTries {
	r := &routeTries{
		trie:        trie.NewTrie[unique.Handle[bypass.ModeEnum]](),
		processTrie: domain.NewDomainMapper[unique.Handle[bypass.ModeEnum]](),
		tagsMap:     make(map[string]struct{}),
	}

	r.processTrie.SetSeparate(filepath.Separator)

	return r
}

func (s *routeTries) insert(uri *Uri, mode unique.Handle[bypass.ModeEnum]) {
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
	db    config.DB
	route *Route
	gc.UnimplementedRulesServer
}

func NewRules(db config.DB, route *Route) *Rules {
	_ = db.View(func(s *pc.Setting) error {
		route.ms.Update(s.GetBypass().GetRulesV2())
		return nil
	})

	return &Rules{
		db:    db,
		route: route,
	}
}

func (r *Rules) List(ctx context.Context, empty *emptypb.Empty) (*gc.RuleResponse, error) {
	names := make([]string, 0)
	err := r.db.View(func(ss *config.Setting) error {
		for _, v := range ss.GetBypass().GetRulesV2() {
			names = append(names, v.GetName())
		}
		return nil
	})

	return gc.RuleResponse_builder{
		Names: names,
	}.Build(), err
}

func (r *Rules) Get(ctx context.Context, index *gc.RuleIndex) (*bypass.Rulev2, error) {
	var resp *bypass.Rulev2
	err := r.db.View(func(ss *config.Setting) error {
		if err := r.checkIndex(ss, index); err != nil {
			return err
		}

		resp = ss.GetBypass().GetRulesV2()[index.GetIndex()]

		return nil
	})

	return resp, err
}

func (r *Rules) Save(ctx context.Context, req *gc.RuleSaveRequest) (*emptypb.Empty, error) {
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

func (r *Rules) Remove(ctx context.Context, index *gc.RuleIndex) (*emptypb.Empty, error) {
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

func (r *Rules) ChangePriority(ctx context.Context, req *gc.ChangePriorityRequest) (*emptypb.Empty, error) {
	err := r.db.Batch(func(s *config.Setting) error {
		if err := r.checkIndex(s, req.GetSource()); err != nil {
			return fmt.Errorf("source index error: %w", err)
		}

		if err := r.checkIndex(s, req.GetTarget()); err != nil {
			return fmt.Errorf("target index error: %w", err)
		}

		src := s.GetBypass().GetRulesV2()[req.GetSource().GetIndex()]
		tar := s.GetBypass().GetRulesV2()[req.GetTarget().GetIndex()]

		s.GetBypass().GetRulesV2()[req.GetSource().GetIndex()] = tar
		s.GetBypass().GetRulesV2()[req.GetTarget().GetIndex()] = src

		r.route.ms.ChangePriority(int(req.GetSource().GetIndex()), int(req.GetTarget().GetIndex()))
		return nil
	})

	return &emptypb.Empty{}, err
}

func (r *Rules) checkIndex(s *config.Setting, index *gc.RuleIndex) error {
	if len(s.GetBypass().GetRulesV2())-1 < int(index.GetIndex()) {
		return fmt.Errorf("can't find rule %d", index.GetIndex())
	}

	rule := s.GetBypass().GetRulesV2()[index.GetIndex()]

	if rule.GetName() != index.GetName() {
		return fmt.Errorf("rule name not match, get: %s, want: %s", rule.GetName(), index.GetName())
	}

	return nil
}
