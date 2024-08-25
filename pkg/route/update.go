package route

import (
	"os"
	"slices"
	"unique"

	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"google.golang.org/protobuf/proto"
)

var myPath string

func init() {
	myPath, _ = os.Executable()
}

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

		if mark.Value().GetTag() != "" {
			trie.tags = append(trie.tags, mark.Value().GetTag())
		}

		for _, hostname := range v.Hostname {
			hostname = TrimComment(hostname)
			scheme, remain := getScheme(hostname)

			if remain == "" {
				continue
			}

			trie.insert(scheme, remain, mark)
		}
	}

	if myPath != "" {
		trie.processTrie[myPath] = unique.Make(bypass.Block)
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

	for s := range rangeRule(c.Bypass.BypassFile) {
		trie.insert(s.Scheme, s.Hostname, s.ModeEnum)

		if s.ModeEnum.Value().GetTag() != "" {
			trie.tags = append(trie.tags, s.ModeEnum.Value().GetTag())
		}
	}

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
