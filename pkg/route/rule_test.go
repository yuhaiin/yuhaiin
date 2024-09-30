package route

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestSplitLine(t *testing.T) {
	t.Log(SplitHostArgs("file:\"/home/asutorufa/.config/yuhaiin/log/yuhaiin.log\" DIRECT,tag=LAN"))
	t.Log(SplitHostArgs("www.google.com PROXY,tag=LAN"))
}

func TestGetScheme(t *testing.T) {
	t.Run("abs path", func(t *testing.T) {
		s := getScheme("file:///a/b/c")
		assert.Equal(t, "file", s.Scheme())
		assert.Equal(t, "/a/b/c", s.Data())
		s.SetData("b/c")
		assert.Equal(t, "b/c", s.Data())
		s.SetData("/c/b/d")
		assert.Equal(t, "/c/b/d", s.Data())
	})

	t.Run("relative path", func(t *testing.T) {
		s := getScheme("file://a/b/c")
		assert.Equal(t, "file", s.Scheme())
		assert.Equal(t, "a/b/c", s.Data())
		s.SetData("b/c")
		assert.Equal(t, "b/c", s.Data())
		s.SetData("/c/b/d")
		assert.Equal(t, "/c/b/d", s.Data())
	})

	t.Run("default domain", func(t *testing.T) {
		s := getScheme("www.google.com")
		assert.Equal(t, "default", s.Scheme())
		assert.Equal(t, "www.google.com", s.Data())
		s.SetData("www.x.com")
		assert.Equal(t, "www.x.com", s.Data())
	})

	t.Run("process", func(t *testing.T) {
		s := getScheme("process:a/b/c")
		assert.Equal(t, "process", s.Scheme())
		assert.Equal(t, "a/b/c", s.Data())
		s = getScheme("process:/a/b/c")
		assert.Equal(t, "process", s.Scheme())
		assert.Equal(t, "/a/b/c", s.Data())
		s = getScheme("process://a/b/c")
		assert.Equal(t, "process", s.Scheme())
		assert.Equal(t, "a/b/c", s.Data())
		s = getScheme("process:///a/b/c")
		assert.Equal(t, "process", s.Scheme())
		assert.Equal(t, "/a/b/c", s.Data())
		s = getScheme("process:a/b c/c")
		assert.Equal(t, "process", s.Scheme())
		assert.Equal(t, "a/b c/c", s.Data())
		s = getScheme("process://C:/a/b c/c")
		assert.Equal(t, "process", s.Scheme())
		assert.Equal(t, "C:/a/b c/c", s.Data())
		s = getScheme("process:C:/a/b c/c")
		assert.Equal(t, "process", s.Scheme())
		assert.Equal(t, "C:/a/b c/c", s.Data())
	})

	t.Run("ip", func(t *testing.T) {
		s := getScheme("ff::ff/64")
		assert.Equal(t, "default", s.Scheme())
		assert.Equal(t, "ff::ff/64", s.Data())
		s = getScheme("ff::ff")
		assert.Equal(t, "default", s.Scheme())
		assert.Equal(t, "ff::ff", s.Data())
		s = getScheme("[ff::ff]")
		assert.Equal(t, "default", s.Scheme())
		assert.Equal(t, "[ff::ff]", s.Data())
		s = getScheme("1.1.1.1/24")
		assert.Equal(t, "default", s.Scheme())
		assert.Equal(t, "1.1.1.1/24", s.Data())
		s = getScheme("1.1.1.1")
		assert.Equal(t, "default", s.Scheme())
		assert.Equal(t, "1.1.1.1", s.Data())
	})
}

func TestSplitHostArgs(t *testing.T) {
	u, args, ok := SplitHostArgs("\"file:///a/b/c/log/test.log\" DIRECT,tag=LAN")
	assert.Equal(t, true, ok)
	assert.Equal(t, "file:///a/b/c/log/test.log", u.String())
	assert.Equal(t, "DIRECT,tag=LAN", args)

	u, args, ok = SplitHostArgs("\"file:///a/b/c/x log/test.log\" DIRECT,tag=LAN")
	assert.Equal(t, true, ok)
	assert.Equal(t, "file:///a/b/c/x log/test.log", u.String())
	assert.Equal(t, "DIRECT,tag=LAN", args)

	u, args, ok = SplitHostArgs("file:///a/b/c/xlog/test.log DIRECT,tag=LAN")
	assert.Equal(t, true, ok)
	assert.Equal(t, "file:///a/b/c/xlog/test.log", u.String())
	assert.Equal(t, "DIRECT,tag=LAN", args)
}

func TestRouteTrie(t *testing.T) {
	r := newRouteTires()

	for _, v := range []string{
		"100.64.0.0/10 PROXY,tag=lan",
		"100.64.0.0/10 PROXY,tag=tailscale",
	} {
		u, mode, err := parseLine(v)
		assert.NoError(t, err)

		r.insert(u, mode)
	}

	m, ok := r.trie.Search(context.Background(), netapi.ParseAddressPort("", "100.112.64.102", 80))
	assert.MustEqual(t, true, ok)
	assert.MustEqual(t, "tailscale", m.Value().GetTag())
}
