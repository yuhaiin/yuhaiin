package dns

import (
	"log"
	"net"
	"testing"
)

func TestDNS7(t *testing.T) {
	log.Println(net.ParseIP("0.0.0.0"))
	_, subnet, _ := net.ParseCIDR("0.0.0.0/0")
	req := createEDNSReq("www.baidu.com", A, createEdnsClientSubnet(subnet))
	t.Log(req)

	b, err := udpDial(req, "8.8.8.8:53")
	if err != nil {
		t.Error(err)
	}
	t.Log(b)
	h, c, err := resolveHeader(req, b)
	if err != nil {
		t.Error(err)
	}
	DNS, ad, err := resolveAnswer(c, h.anCount, b)
	if err != nil {
		t.Error(err)
	}
	log.Println(DNS, len(ad))
	resolveAdditional(ad, h.arCount)
}

func TestMask(t *testing.T) {
	_, s, err := net.ParseCIDR("ff::1/20")
	if err != nil {
		t.Error(err)
	}
	t.Log(s.Mask.Size())
	t.Log(s.IP)

}
