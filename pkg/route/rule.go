package route

import (
	"bufio"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
)

var deafultRule = `
0.0.0.0/8 DIRECT,tag=LAN
10.0.0.0/8 DIRECT,tag=LAN
100.64.0.0/10 DIRECT,tag=LAN
127.0.0.0/8 DIRECT,tag=LAN
169.254.0.0/16 DIRECT,tag=LAN
172.16.0.0/12 DIRECT,tag=LAN
192.0.0.0/29 DIRECT,tag=LAN
192.0.2.0/24 DIRECT,tag=LAN
192.88.99.0/24 DIRECT,tag=LAN
192.168.0.0/16 DIRECT,tag=LAN
198.18.0.0/15 DIRECT,tag=LAN
198.51.100.0/24 DIRECT,tag=LAN
203.0.113.0/24 DIRECT,tag=LAN
224.0.0.0/3 DIRECT,tag=LAN
localhost DIRECT,tag=LAN
`

type Rule struct {
	ModeEnum unique.Handle[bypass.ModeEnum]
	Scheme   string
	Hostname string
}

func rangeRule(path string) iter.Seq[Rule] {
	return func(f func(Rule) bool) {
		var reader io.ReadCloser
		var err error
		reader, err = os.Open(path)
		if err != nil {
			log.Error("open bypass file failed, fallback to use internal bypass data",
				slog.String("filepath", path), slog.Any("err", err))

			reader = io.NopCloser(strings.NewReader(deafultRule))
		}
		defer reader.Close()

		br := bufio.NewScanner(reader)

		for br.Scan() {
			before := TrimComment(br.Text())

			scheme, hostname, args, ok := SplitHostArgs(before)
			if !ok {
				continue
			}

			modeEnum, ok := SplitModeArgs(args)
			if !ok {
				continue
			}

			r := Rule{
				Scheme:   scheme,
				ModeEnum: modeEnum,
				Hostname: hostname,
			}

			if r.Scheme == "file" && !filepath.IsAbs(r.Hostname) {
				r.Hostname = filepath.Join(filepath.Dir(path), r.Hostname)
			}

			if !f(r) {
				return
			}
		}
	}
}

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

func SplitHostArgs(s string) (scheme, hostname, args string, ok bool) {
	scheme, s = getScheme(s)

	if len(s) == 0 {
		return
	}

	if s[0] == '"' || s[0] == '\'' {
		i := strings.IndexByte(s[1:], s[0])
		if i == -1 {
			return
		}

		hostname = s[1 : i+1]
		args = strings.TrimSpace(s[i+2:])
		ok = true
		return
	}

	i := strings.IndexByte(s, ' ')
	if i == -1 {
		return
	}

	hostname = s[:i]
	args = strings.TrimSpace(s[i+1:])
	ok = true
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
		return
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

func getScheme(h string) (string, string) {
	i := strings.Index(h, ":")
	if i == -1 {
		return "", h
	}

	switch h[:i] {
	case "file", "process":
		return h[:i], h[i+1:]
	default:
		return "", h
	}
}

type routeTries struct {
	trie        *trie.Trie[unique.Handle[bypass.ModeEnum]]
	processTrie map[string]unique.Handle[bypass.ModeEnum]
	tags        []string
}

func newRouteTires() *routeTries {
	return &routeTries{
		trie:        trie.NewTrie[unique.Handle[bypass.ModeEnum]](),
		processTrie: make(map[string]unique.Handle[bypass.ModeEnum]),
		tags:        []string{},
	}
}

func (s *routeTries) insert(scheme, host string, mode unique.Handle[bypass.ModeEnum]) {
	switch scheme {
	case "file":
		for x := range slice.RangeFileByLine(host) {
			x = TrimComment(x)
			if x == "" {
				continue
			}

			scheme, hostname := getScheme(x)
			if scheme == "file" && !filepath.IsAbs(hostname) {
				hostname = filepath.Join(filepath.Dir(host), hostname)
			}

			s.insert(scheme, hostname, mode)
		}

	case "process":
		s.processTrie[host] = mode
	default:
		s.trie.Insert(strings.ToLower(host), mode)
	}
}
