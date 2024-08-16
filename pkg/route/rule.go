package route

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
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

func rangeRule(path string) func(f func(string, bypass.ModeEnum) bool) {
	var reader io.ReadCloser
	var err error
	reader, err = os.Open(path)
	if err != nil {
		log.Error("open bypass file failed, fallback to use internal bypass data",
			slog.String("filepath", path), slog.Any("err", err))

		reader = io.NopCloser(strings.NewReader(deafultRule))
	}

	return func(f func(string, bypass.ModeEnum) bool) {
		defer reader.Close()

		br := bufio.NewScanner(reader)

		for br.Scan() {
			before := TrimComment(br.Text())

			hostname, args, ok := SplitHostArgs(before)
			if !ok {
				continue
			}

			mode, modeargs, ok := SplitModeArgs(args)
			if !ok {
				continue
			}

			modeEnum := ParseArgs(mode, modeargs).ToModeConfig(nil).ToModeEnum()

			if !strings.HasPrefix(hostname, "file:") {
				if !f(strings.ToLower(hostname), modeEnum) {
					return
				}
				continue
			}

			file := hostname[5:]
			if !filepath.IsAbs(file) {
				file = filepath.Join(filepath.Dir(path), file)
			}

			for x := range slice.RangeFileByLine(file) {
				if !f(x, modeEnum) {
					return
				}
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
func ParseArgs(mode bypass.Mode, fs []string) Args {
	f := Args{Mode: mode}

	for _, x := range fs {
		var k, v string
		i := strings.IndexByte(x, '=')
		if i == -1 {
			k = x
			v = "true"
		} else {
			k = x[:i]
			v = x[i+1:]
		}

		key := strings.ToLower(k)
		value := strings.ToLower(v)

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
	before, _, _ := strings.Cut(s, "#")
	return before
}

func SplitHostArgs(s string) (hostname, args string, ok bool) {
	if strings.HasPrefix(s, "file:") {
		etc := s[5:]

		if len(etc) == 0 {
			return
		}

		if etc[0] == '"' || etc[0] == '\'' {
			i := strings.IndexByte(etc[1:], etc[0])
			if i == -1 {
				return
			}

			hostname = "file:" + etc[1:i+1]
			args = strings.TrimSpace(etc[i+2:])
			ok = true
			return
		}
	}

	fields := strings.Fields(s)

	if len(fields) < 2 {
		return
	}

	hostname = fields[0]
	args = strings.Join(fields[1:], " ")
	ok = true

	return
}

func SplitModeArgs(s string) (mode bypass.Mode, args []string, ok bool) {
	fs := strings.FieldsFunc(s, func(r rune) bool { return r == ',' })
	if len(fs) < 1 {
		return
	}

	modestr := strings.ToLower(fs[0])

	mode = bypass.Mode(bypass.Mode_value[modestr])

	if mode.Unknown() {
		return
	}

	args = fs[1:]
	ok = true

	return
}
