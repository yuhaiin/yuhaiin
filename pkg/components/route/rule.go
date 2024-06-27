package route

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/yuhaiin/kitte"
)

func rangeRule(path string, ranger func(string, bypass.ModeEnum)) {
	var reader io.ReadCloser
	var err error
	reader, err = os.Open(path)
	if err != nil {
		log.Error("open bypass file failed, fallback to use internal bypass data",
			slog.String("filepath", path), slog.Any("err", err))

		reader = io.NopCloser(bytes.NewReader(kitte.Content))
	}
	defer reader.Close()

	br := bufio.NewScanner(reader)

	for br.Scan() {
		before, _, _ := bytes.Cut(br.Bytes(), []byte{'#'})
		fields := bytes.Fields(before)
		if len(fields) < 2 {
			continue
		}

		hostname := strings.ToLower(string(fields[0]))
		args := fields[1]

		fs := bytes.FieldsFunc(args, func(r rune) bool {
			return r == ','
		})

		if len(fs) < 1 {
			continue
		}

		modestr := strings.ToLower(string(fs[0]))

		mode := bypass.Mode(bypass.Mode_value[modestr])

		if mode.Unknown() {
			continue
		}

		ranger(hostname, ParseArgs(mode, fs[1:]).ToModeConfig(nil).ToModeEnum())
	}
}

type Args struct {
	Mode                 bypass.Mode
	Tag                  string
	ResolveStrategy      bypass.ResolveStrategy
	UdpProxyFqdnStrategy bypass.UdpProxyFqdnStrategy
}

// ParseArgs parse args
// args: tag=tag,udp_proxy_fqdn,resolve_strategy=prefer_ipv6
func ParseArgs(mode bypass.Mode, fs [][]byte) Args {
	f := Args{Mode: mode}

	for _, x := range fs {
		var k, v []byte
		i := bytes.IndexByte(x, '=')
		if i == -1 {
			k = x
			v = []byte("true")
		} else {
			k = x[:i]
			v = x[i+1:]
		}

		key := strings.ToLower(string(k))
		value := strings.ToLower(string(v))

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
