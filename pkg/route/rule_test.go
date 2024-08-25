package route

import "testing"

func TestSplitLine(t *testing.T) {
	t.Log(SplitHostArgs("file:\"/home/asutorufa/.config/yuhaiin/log/yuhaiin.log\" DIRECT,tag=LAN"))
	t.Log(SplitHostArgs("www.google.com PROXY,tag=LAN"))
}

func TestRangeRule(t *testing.T) {
	for v := range rangeRule("xx") {
		t.Log(v.Hostname, v.ModeEnum.Value())
	}
}
