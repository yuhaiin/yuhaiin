package dns

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/net/common"
)

func TestDNS8(t *testing.T) {
	header, x := createDNSSEC("www.cloudflare.com", A)
	//log.Println(x)
	var b = common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(b)
	b, err := post(x, "cloudflare-dns.com")
	if err != nil {
		t.Error(err)
	}
	s, c, err := resolveHeader(header.DnsHeader, b)
	if err != nil {
		t.Error(err)
	}
	t.Log(resolveAnswer(c, s.anCount, b))
	//t.Log(b)
}
