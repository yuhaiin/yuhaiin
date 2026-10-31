package domain

import (
	"testing"
)

func TestDelete(t *testing.T) {
	x := &trie[string]{Child: map[string]*trie[string]{}}
	insert(x, newReader("www.baidu.com", '.'), "baidu")
	insert(x, newReader("www.google.com", '.'), "google")
	insert(x, newReader("www.twitter.com", '.'), "twitter")
	insert(x, newReader("www.x.twitter.com", '.'), "twitter.x")
	insert(x, newReader("*.x.com", '.'), "*.x")
	insert(x, newReader("www.xvv.*", '.'), "xvv.*")
	expect := func(domain, want string, found bool) {
		t.Helper()
		got, ok := search(x, newReader(domain, '.'))
		if got != want || ok != found {
			t.Fatalf("search(%q) = %q, %v; want %q, %v", domain, got, ok, want, found)
		}
	}

	remove(x, newReader("www.baidu.com", '.'))

	expect("www.baidu.com", "", false)

	remove(x, newReader("www.twitter.com", '.'))
	remove(x, newReader("www.vv.x.com", '.'))

	expect("www.twitter.com", "", false)
	expect("www.x.twitter.com", "twitter.x", true)
	expect("www.vv.x.com", "*.x", true)

	remove(x, newReader("*.x.com", '.'))
	expect("www.vv.x.com", "", false)
	expect("www.xvv.com.cn", "xvv.*", true)

	remove(x, newReader("www.xvv.*", '.'))
	expect("www.xvv.com.cn", "", false)
	expect("www.google.com", "google", true)
}
