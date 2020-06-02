package dns

import (
	"log"
	"net"
	"testing"
)

func TestDNS7(t *testing.T) {
	log.Println(net.ParseIP("0.0.0.0"))
	req := createEDNSReq("www.baidu.com", A, createEdnsClientSubnet(net.ParseIP("114.114.114.114")))
	t.Log(req)

	b, err := udpDial(req, "223.5.5.5:53")
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
	log.Println(DNS)
	resolveAdditional(ad, h.arCount)
}
