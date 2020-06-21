package process

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
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

func TestMatch(t *testing.T) {

	type modeStruct struct {
		Type  todo
		other string
	}

	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		t.Error(err)
	}

	f, err := os.Open(conFig.BypassFile)
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	Matcher = match.NewMatch(conFig.DnsServer, conFig.IsDNSOverHTTPS)

	br := bufio.NewReader(f)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		var domain string
		var mode string
		if _, err := fmt.Sscanf(string(a), "%s %s", &domain, &mode); err != nil {
			continue
		}
		//log.Println(domain,mode)
		//if strings.Contains(domain,"163.com"){
		//	log.Println(domain,mode)
		//}

		if err = Matcher.Insert(domain, modeStruct{Type: modes[strings.ToLower(mode)], other: "DIRECTDOH://dns.alidns.com"}); err != nil {
			log.Println(err)
			continue
		}
	}

	t.Log(Matcher.Search("163.com"))
	t.Log(Matcher.Search("music.163.com"))
	t.Log(Matcher.Search("m701.music.126.net"))
	t.Log(Matcher.Search("s2.music.126.net"))
	t.Log(Matcher.Search("tieba.baidu.com"))
	t.Log(Matcher.Search("api.github.com"))
	t.Log(Matcher.Search("cdn.v2ex.com"))
	t.Log(Matcher.Search("aod-image-material.cdn.bcebos.com"))
	select {}
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
	s, _ := config.SettingDecodeJSON()
	SetConFig(s)
}
