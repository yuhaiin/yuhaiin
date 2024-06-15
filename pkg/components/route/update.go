package route

import (
	"os"
	"slices"
	"strings"

	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"google.golang.org/protobuf/proto"
)

func (s *Route) updateCustomRule(c *pc.Setting) {
	if slices.EqualFunc(
		s.config.CustomRuleV3,
		c.Bypass.CustomRuleV3,
		func(mc1, mc2 *bypass.ModeConfig) bool { return proto.Equal(mc1, mc2) },
	) {
		return
	}

	trie := newRouteTires()

	for _, v := range c.Bypass.CustomRuleV3 {
		mark := v.ToModeEnum()

		if mark.GetTag() != "" {
			trie.tags = append(trie.tags, mark.GetTag())
		}

		for _, hostname := range v.Hostname {
			hostname, _, _ := strings.Cut(hostname, "#")
			scheme, remain := getScheme(hostname)

			if remain == "" {
				continue
			}

			switch scheme {
			case "file":
				slice.RangeFileByLine(remain, func(x string) {
					trie.trie.Insert(x, mark)
				})

			case "process":
				trie.processTrie[remain] = mark
			default:
				trie.trie.Insert(remain, mark)
			}
		}
	}

	s.customTrie = trie
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

func (s *Route) updateRulefile(c *pc.Setting) {
	modifiedTime := s.modifiedTime
	if stat, err := os.Stat(c.Bypass.BypassFile); err == nil {
		modifiedTime = stat.ModTime().Unix()
	}

	if s.config.BypassFile == c.Bypass.BypassFile && s.modifiedTime == modifiedTime {
		return
	}

	trie := newRouteTires()
	s.modifiedTime = modifiedTime

	rangeRule(c.Bypass.BypassFile, func(s1 string, s2 bypass.ModeEnum) {
		if strings.HasPrefix(s1, "process:") {
			trie.processTrie[s1[8:]] = s2.Mode()
		} else {
			trie.trie.Insert(s1, s2)
		}

		if s2.GetTag() != "" {
			trie.tags = append(trie.tags, s2.GetTag())
		}
	})

	s.trie = trie
}

func (s *Route) Update(c *pc.Setting) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resolveDomain = c.Dns.ResolveRemoteDomain
	s.updateCustomRule(c)
	s.updateRulefile(c)
	s.config = c.Bypass
}
