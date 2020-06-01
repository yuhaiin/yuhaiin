package dns

import "testing"

func TestDNS7(t *testing.T) {
	req := createEDNSReq("www.baidu.com", "114.114.114.114")
	t.Log(req)

	b, err := udpDial(req, "223.5.5.5:53")
	if err != nil {
		t.Error(err)
	}
	t.Log(b)
}
