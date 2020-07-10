package controller

import (
	"log"
	"net"
	"net/url"
	"testing"
)

func TestReadline(t *testing.T) {
	modes := map[string]int{"direct": 0, "proxy": 1, "block": 2}
	t.Log(modes["test"], modes["direct"], modes["block"], modes["block2"])
}

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

func TestNewMatchCon(t *testing.T) {
	s := func(option MatchConOption) {
		o := &OptionMatchCon{}
		option(o)
		log.Println(o)
	}
	s(func(option *OptionMatchCon) {
		option.DNS.Server = "114.114.114.114"
	})
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
