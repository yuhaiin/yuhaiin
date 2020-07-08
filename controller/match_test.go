package controller

import (
	"log"
	"net"
	"net/url"
	"testing"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/net/match"
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

func TestUpdateDNS(t *testing.T) {
	var (
		con *config.Setting
		ma  *match.Match
	)
	t.Log(con, con == nil, ma)
}
