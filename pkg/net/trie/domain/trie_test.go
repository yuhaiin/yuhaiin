package domain

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDelete(t *testing.T) {
	x := &trie[string]{Child: map[string]*trie[string]{}}
	insert(x, newReader("www.baidu.com"), "baidu")
	insert(x, newReader("www.google.com"), "google")
	insert(x, newReader("www.twitter.com"), "twitter")
	insert(x, newReader("www.x.twitter.com"), "twitter.x")
	insert(x, newReader("*.x.com"), "*.x")
	insert(x, newReader("www.xvv.*"), "xvv.*")

	remove(x, newReader("www.baidu.com"))

	t.Log(search(x, newReader("www.baidu.com")))

	remove(x, newReader("www.twitter.com"))
	remove(x, newReader("www.vv.x.com"))

	t.Log(search(x, newReader("www.twitter.com")))
	t.Log(search(x, newReader("www.x.twitter.com")))
	t.Log(search(x, newReader("www.vv.x.com")))

	remove(x, newReader("*.x.com"))
	t.Log(search(x, newReader("www.vv.x.com")))
	t.Log(search(x, newReader("www.xvv.com.cn")))

	remove(x, newReader("www.xvv.*"))
	t.Log(search(x, newReader("www.xvv.com.cn")))
}

func TestTrieDomainMatcherSearch(t *testing.T) {
	root := &trie[string]{Child: map[string]*trie[string]{}}
	insert(root, newReader("*.baidu.com"), "sub_baidu_test")
	insert(root, newReader("www.baidu.com"), "test_baidu")
	insert(root, newReader("last.baidu.*"), "test_last_baidu")
	insert(root, newReader("*.baidu.*"), "last_sub_baidu_test")
	insert(root, newReader("spo.baidu.com"), "test_no_sub_baidu")
	insert(root, newReader("www.google.com"), "test_google")
	insert(root, newReader("music.111.com"), "1111")
	insert(root, newReader("163.com"), "163")
	insert(root, newReader("*.google.com"), "google")
	insert(root, newReader("*.dl.google.com"), "google_dl")
	insert(root, newReader("api.sec.miui.*"), "ad_miui")
	insert(root, newReader("*.miui.com"), "miui")
	insert(root, newReader("*.x.*"), "x_all")
	insert(root, newReader("*.x.com"), "x_com")
	insert(root, newReader("www.x.*"), "www_x")

	search := func(s string) string {
		res, _ := search(root, newReader(s))
		return res
	}

	assert.Equal(t, "test_baidu", search("www.baidu.com"))
	assert.Equal(t, "test_no_sub_baidu", search("spo.baidu.com"))
	assert.Equal(t, "test_last_baidu", search("last.baidu.com.cn"))
	assert.Equal(t, "sub_baidu_test", search("test.baidu.com"))
	assert.Equal(t, "sub_baidu_test", search("test.test2.baidu.com"))
	assert.Equal(t, "last_sub_baidu_test", search("www.baidu.cn"))
	assert.Equal(t, "test_google", search("www.google.com"))
	assert.Equal(t, "", search("www.google.cn"))
	assert.Equal(t, "", search("music.163.com"))
	assert.Equal(t, "163", search("163.com"))
	assert.Equal(t, "google", search("www.x.google.com"))
	assert.Equal(t, "google_dl", search("dl.google.com"))
	assert.Equal(t, "ad_miui", search("api.sec.miui.com"))
	assert.Equal(t, "x_all", search("a.x.x.net"))
	assert.Equal(t, "x_com", search("a.x.com"))
	assert.Equal(t, "www_x", search("www.x.z"))
}
