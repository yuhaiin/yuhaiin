package route

import (
	"os"
	"slices"
	"strings"

	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
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
			if strings.HasPrefix(hostname, "process:") {
				trie.processTrie[hostname[8:]] = mark
			} else {
				trie.trie.Insert(hostname, mark)
			}
		}
	}

	s.customTrie = trie
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
