package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDNS(t *testing.T) {
	URI, err := url.Parse("//" + "baidu.com:443")
	if err != nil {
		t.Error(err)
	}
	t.Log(URI.Hostname())
}

func TestForward(t *testing.T) {
	x, err := url.Parse("//" + "aaaaa.aaaa")
	if err != nil {
		t.Error(err)
	}
	log.Println(x.Hostname())

	f := func() []byte { return nil }
	if f() == nil {
		log.Println("nil")
	}
	log.Println(len(f()))
}

func TestForward2(t *testing.T) {
	c, err := url.Parse("DIRECTDOH://dns.alidns.com")
	if err != nil {
		t.Error(err)
	}
	t.Log(c.Scheme, c.Host)
	c, err = url.Parse("DIRECT://")
	if err != nil {
		t.Error(err)
	}
	t.Log(c.Scheme, c.Host)
}

func TestUpdateDNSSubNet(t *testing.T) {
	x, _ := url.Parse("//" + "dns.nextdns.io/e28bb3")
	t.Log(x.Hostname(), x.Host, x.Path)
	t.Log(net.ParseIP(x.Hostname()))
}

func TestPrintPointer(t *testing.T) {
	var a *string
	a = new(string)
	t.Logf("%p %s", a, *a)
	*a = "a"
	t.Logf("%p %s", a, *a)
	b := "b"
	a = &b
	t.Logf("%p %s", a, *a)

	type test struct {
		name string
	}

	c := &test{name: "c"}
	t.Logf("%p %v", c, c)
	*c = test{name: "cc"}
	t.Logf("%p %v", c, c)
	c = &test{name: "ccc"}
	t.Logf("%p %v", c, c)

	d := func() {}
	t.Logf("%p", d)
	d = func() {}
	t.Logf("%p", d)

	e := func() {}
	d = e
	t.Logf("%p", d)
}

func TestDeepEqual(t *testing.T) {
	a := func() {}
	b := a
	c := func() {}
	t.Logf("%p %p %p", a, b, c)
	t.Log(reflect.DeepEqual(a, b))
	t.Log(reflect.DeepEqual(a, c))
	t.Log(&a, &b, &a == &b)
	t.Log(&a == &c)

	aa := reflect.ValueOf(a)
	bb := reflect.ValueOf(b)
	t.Log(aa.Pointer(), bb.Pointer(), aa.Pointer() == bb.Pointer(), &aa)
}

type aa struct {
	a string
}

func (a *aa) test() {}

func TestFuncEqual(t *testing.T) {
	a := &aa{a: "a"}
	b := &aa{a: "b"}

	t.Log(reflect.ValueOf(&a.a).Pointer(), reflect.ValueOf(&b.a).Pointer())
	t.Log(reflect.ValueOf(a.test).Pointer(), reflect.ValueOf(b.test).Pointer(), reflect.ValueOf((*aa).test).Pointer())
	t.Logf("%p %p", a.test, b.test)

	c := a.test
	d := b.test
	e := b.test
	t.Log(&c, &d, &e)

	f := func(x func()) {
		t.Log(reflect.DeepEqual(x, a.test))
		a := x
		t.Log(reflect.ValueOf(x).Pointer(), &a)
	}
	g := a.test
	t.Log(reflect.ValueOf(a.test).Pointer(), &g)
	f(a.test)
}

func TestStructChange(t *testing.T) {
	type a struct {
		aa string
	}
	f := func(a *a, str string) {
		a.aa = str
	}

	b := &a{aa: "b"}
	c := b
	f(c, "c:=b")
	d := &a{}
	*d = *b
	log.Println("d", d)
	f(d, "*d = *b")
	log.Println(c, b, d)
}

func TestResolver(t *testing.T) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			t.Log(network, address)
			return net.Dial("tcp", "114.114.114.114:53")
		},
	}
	t.Log(resolver.LookupIPAddr(context.Background(), "www.baidu.com"))
}

func TestScanf(t *testing.T) {
	str := "a b"
	var a string
	var b string
	if strings.HasPrefix(str, "#") {
		t.Error("comment")
		return
	}
	_, err := fmt.Sscanf("a = b", "%s = %s", &a, &b)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(a, b)

	re, err := regexp.Compile("^([^ ]+) +([^ ]+) *$")
	if err != nil {
		t.Error(err)
	}

	c := re.FindStringSubmatch("a bb")
	t.Log(len(c), c[1], c[2])

	e := re.FindSubmatch([]byte("1.* Ba+2"))
	t.Log(string(e[1]), string(e[2]))

	d := re.FindAllStringSubmatch("v   aaaaccc", -1)
	t.Log(len(d), d)
}
func TestValue(t *testing.T) {
	var z atomic.Value
	z.Store(func() {})
	t.Log(z.Load())
	var x func()
	z.Store(x)
	t.Log(z.Load())
}
