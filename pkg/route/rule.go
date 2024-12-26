package route

import (
	"net/url"
	"path/filepath"
	"strings"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
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
	return &bypass.ModeConfig{
		Mode:                 a.Mode,
		Tag:                  a.Tag,
		Hostname:             hostname,
		ResolveStrategy:      a.ResolveStrategy,
		UdpProxyFqdnStrategy: a.UdpProxyFqdnStrategy,
	}
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
	for i := 0; i < len(a); i++ {
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
