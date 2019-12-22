package cidrmatch

import (
	"net"
	"testing"
)

func TestCidrMatch_InsetOneCIDR(t *testing.T) {
	cidrMatch := NewCidrMatch()
	if err := cidrMatch.InsetOneCIDR("10.2.2.1/18", "testIPv4"); err != nil {
		t.Error(err)
	}
	if err := cidrMatch.InsetOneCIDR("2001:0db8:0000:0000:1234:0000:0000:9abc/32", "testIPv6"); err != nil {
		t.Error(err)
	}
	testIPv4 := "10.2.2.1"
	testIPv4b := "100.2.2.1"
	testIPv6 := "2001:0db8:0000:0000:1234:0000:0000:9abc"
	testIPv6b := "3001:0db8:0000:0000:1234:0000:0000:9abc"
	t.Log(cidrMatch.MatchOneIP(testIPv4))
	t.Log(cidrMatch.MatchOneIP(testIPv6))
	t.Log(cidrMatch.MatchOneIP(testIPv4b))
	t.Log(cidrMatch.MatchOneIP(testIPv6b))
}

func BenchmarkCidrMatch_MatchOneIP(b *testing.B) {
	b.StopTimer() //调用该函数停止压力测试的时间计数

	//做一些初始化的工作,例如读取文件数据,数据库连接之类的,
	//这样这些时间不影响我们测试函数本身的性能
	cidrMatch := NewCidrMatch()
	if err := cidrMatch.InsetOneCIDR("10.2.2.1/18", "testIPv4"); err != nil {
		b.Error(err)
	}
	if err := cidrMatch.InsetOneCIDR("2001:0db8:0000:0000:1234:0000:0000:9abc/32", "testIPv6"); err != nil {
		b.Error(err)
	}
	//testIPv4 := "10.2.2.1"
	//testIPv4b := "100.2.2.1"
	//testIPv6 := "2001:0db8:0000:0000:1234:0000:0000:9abc"
	testIPv6b := "3001:0db8:0000:0000:1234:0000:0000:9abc"
	b.StartTimer() //重新开始时间
	for i := 0; i < b.N; i++ {
		//cidrMatch.MatchOneIP(testIPv4)
		//cidrMatch.MatchOneIP(testIPv6)
		//cidrMatch.MatchOneIP(testIPv4b)
		cidrMatch.MatchOneIP(testIPv6b)
	}
}

func BenchmarkIpv6AddrToInt2(b *testing.B) {
	b.StopTimer()
	S := "ffff:fff2:ffff:ffff:ffff:ffff:ffff:ffff"
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Ipv6AddrToInt2(S)
	}
}

func BenchmarkIpv6AddrToInt(b *testing.B) {
	b.StopTimer()
	S := "ffff:fff2:ffff:ffff:ffff:ffff:ffff:ffff"
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Ipv6AddrToInt(S)
	}
}

func BenchmarkToIpv6(b *testing.B) {
	b.StopTimer()
	S := "::ffff:fff2:ffff:ffff:ffff"
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Log(ToIpv6(S))
	}
}

func BenchmarkToIpv62(b *testing.B) {
	b.StopTimer()
	S := "::ffff:fff2:ffff:ffff:ffff"
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Log(net.ParseIP(S).To16())
	}
}

func BenchmarkIpAddrToInt(b *testing.B) {
	str := "0.0.255.255"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.Log(IpAddrToInt(str))
	}
}
