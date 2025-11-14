package route

import (
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
)

func TestCovertPath(t *testing.T) {
	t.Log(filepath.Join("C:", `/s/d/s`))
	t.Log(convertVolumeName("/d/d/s/s/s"))
	t.Log(filepath.Clean(`lib\firefox/firefox`))
	t.Log(filepath.Clean("a.a.a.c"))
}

func TestMatch(t *testing.T) {
	nc := domain.NewTrie[string]()
	nc.SetSeparate(filepath.Separator)

	nc.Insert(convertVolumeName("/usr/bin/transmission-daemon"), "xxxx")

	t.Log(nc.SearchString(convertVolumeName("/usr/bin/transmission-daemon")))
}

func TestParse(t *testing.T) {
	t.Log(netapi.ParseAddress("", "[ff::ff]"))
}
