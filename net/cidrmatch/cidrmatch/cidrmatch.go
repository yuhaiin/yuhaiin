package cidrmatch

import (
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
)

// CidrMatch <--
type CidrMatch struct {
	masksize int
	cidrMap  map[string][]*net.IPNet
	cidrS    []*net.IPNet
}

func (cidrmatch *CidrMatch) MatchString(ip string) bool {
	ss := net.ParseIP(ip)
	for _, n := range cidrmatch.cidrS {
		// log.Println(s, n)
		if n.Contains(ss) {
			return true
		}
	}
	return false
}

func (cidrmatch *CidrMatch) Match(ip net.IP) bool {
	for _, n := range cidrmatch.cidrS {
		// log.Println(s, n)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// NewCidrMatch <--
func NewCidrMatch(fileName string) (*CidrMatch, error) {
	cidrmatch := new(CidrMatch)
	configTemp, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Println(err)
		return cidrmatch, err
	}
	for _, n := range strings.Split(string(configTemp), "\n") {
		_, cidr, err := net.ParseCIDR(n)
		if err != nil {
			continue
		}
		cidrmatch.cidrS = append(cidrmatch.cidrS, cidr)
	}
	return cidrmatch, nil
}

// NewCidrMatchWithCidranger <--
func NewCidrMatchWithMap(fileName string) (*CidrMatch, error) {
	cidrmatch := new(CidrMatch)
	cidrmatch.masksize = cidrmatch.getMaskSize(fileName)
	cidrmatch.cidrMap = cidrmatch.getCidrMap(fileName)
	return cidrmatch, nil
}

func (cidrmatch *CidrMatch) getMaskSize(fileName string) int {
	configTemp, _ := ioutil.ReadFile(fileName)
	match := map[int]bool{}
	// ip := "255.1.1.1/24"
	for _, cidr := range strings.Split(string(configTemp), "\n") {
		_, cidr2, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		masksize, _ := cidr2.Mask.Size()
		if !match[masksize] {
			match[masksize] = true
		}
	}
	// log.Println(match)
	masksize := 32
	for key := range match {
		if key < masksize {
			masksize = key
		}
	}
	return masksize
}

func (cidrmatch *CidrMatch) getCidrMap(fileName string) map[string][]*net.IPNet {
	configTemp, _ := ioutil.ReadFile(fileName)
	match := map[string][]*net.IPNet{}
	for _, cidr := range strings.Split(string(configTemp), "\n") {
		_, cidr2, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		/* 十进制转化为二进制 */
		c := ""
		if cidr2.IP.To4() != nil {
			c = ipAddrToInt(cidr2.IP.String())
		} else {
			c = ipv6AddrToInt(toIpv6(cidr2.IP.String()))
		}
		// fmt.Println("c:", c)
		/* 二进制转化为十进制 */
		// d, err := strconv.ParseInt(c, 2, 64)
		// fmt.Println("d:", d, err)
		prefix := c[:cidrmatch.masksize]
		match[prefix] = append(match[prefix], cidr2)
	}
	return match
}

func (cidrmatch *CidrMatch) ipGetKey(ip string) string {
	/* 十进制转化为二进制 */
	ipTmp := net.ParseIP(ip)
	if ipTmp.To4() != nil {
		return ipAddrToInt(ip)[:cidrmatch.masksize]
	} else if ipTmp.To16() != nil {
		return ipv6AddrToInt(toIpv6(ip))[:cidrmatch.masksize]
	}
	return ""
}

func (cidrmatch *CidrMatch) MatchWithMap(ip string) bool {
	mapIP := cidrmatch.cidrMap[cidrmatch.ipGetKey(ip)]
	if len(mapIP) == 0 {
		return false
	}
	for _, s := range mapIP {
		if s.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func ipAddrToInt(ipAddr string) string {
	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	var sum int64
	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)
	c := strconv.FormatInt(sum, 2)
	nowlong := 32 - len(c)
	for i := 0; i < nowlong; i++ {
		c = "0" + c
	}
	return c
}

func toIpv6(ip string) string {
	// ip := "2001:b28:f23d:f001::a"
	// log.Println(strings.Split(ip, "::"))
	// log.Println(strings.Split(strings.Split(ip, "::")[0], ":"))
	// log.Println(strings.Split(strings.Split(ip, "::")[1], ":"))
	// log.Println(8 - len(strings.Split(strings.Split(ip, "::")[0], ":")) - len(strings.Split(strings.Split(ip, "::")[1], ":")))
	if !strings.Contains(ip, "::") {
		return ip
	}
	firstSub := strings.Split(ip, "::")
	ipv6b1 := firstSub[0]
	ipv6b2 := firstSub[1]
	b1, b2 := len(ipv6b1), len(ipv6b2)
	needZero := 0
	if b1 == 0 {
		needZero = 8 - len(strings.Split(ipv6b2, ":"))
	} else {
		needZero = 8 - len(strings.Split(ipv6b1, ":")) - len(strings.Split(ipv6b2, ":"))
	}
	// log.Println(ipv6b1, "--", ipv6b2, "--", needZero, len(strings.Split(ipv6b1, ":")), len(strings.Split(ipv6b2, ":")))
	for i := 0; i < needZero; i++ {
		if b1 == 0 {
			ipv6b1 = ipv6b1 + "0:"
			if i == needZero-1 {
				ipv6b1 = ipv6b1 + ipv6b2
			}
		} else if b2 == 0 {
			ipv6b1 = ipv6b1 + ":0"
			if i == needZero-1 {
				ipv6b1 = ipv6b1 + ":0"
			}
		} else {
			ipv6b1 = ipv6b1 + ":0"
			if i == needZero-1 {
				ipv6b1 = ipv6b1 + ":" + ipv6b2
			}
		}
		// log.Println(ipv6b1)
	}
	return ipv6b1
}

func ipv6AddrToInt(ipAddr string) string {
	bits := strings.Split(ipAddr, ":")
	b0, _ := strconv.ParseInt(bits[0], 16, 64)
	b1, _ := strconv.ParseInt(bits[1], 16, 64)
	b2, _ := strconv.ParseInt(bits[2], 16, 64)
	b3, _ := strconv.ParseInt(bits[3], 16, 64)
	b4, _ := strconv.ParseInt(bits[4], 16, 64)
	b5, _ := strconv.ParseInt(bits[5], 16, 64)
	b6, _ := strconv.ParseInt(bits[6], 16, 64)
	b7, _ := strconv.ParseInt(bits[7], 16, 64)
	var sum1, sum2, sum3, sum4 int64
	var sum1S, sum2S, sum3S, sum4S string

	if b0 == 0 {
		sum1 += int64(b0) + 1<<16
		sum1 += int64(b1)
		sum1S = strconv.FormatInt(sum1, 2)[1:]
		nowlong := 32 - len(sum1S)
		for i := 0; i < nowlong; i++ {
			sum1S = "0" + sum1S
		}
	} else {
		sum1 += int64(b0) << 16
		sum1 += int64(b1)
		sum1S = strconv.FormatInt(sum1, 2)
		log.Println(sum1S)
		nowlong := 32 - len(sum1S)
		for i := 0; i < nowlong; i++ {
			sum1S = "0" + sum1S
		}
	}

	if b0 == 0 {
		sum2 += int64(b2) + 1<<16
		sum2 += int64(b3)
		sum2S = strconv.FormatInt(sum2, 2)[1:]
		nowlong := 32 - len(sum2S)
		for i := 0; i < nowlong; i++ {
			sum2S = "0" + sum2S
		}
	} else {
		sum2 += int64(b2) << 16
		sum2 += int64(b3)
		sum2S = strconv.FormatInt(sum2, 2)
		nowlong := 32 - len(sum2S)
		for i := 0; i < nowlong; i++ {
			sum2S = "0" + sum2S
		}
	}

	if b0 == 0 {
		sum3 += int64(b4) + 1<<16
		sum3 += int64(b5)
		sum3S = strconv.FormatInt(sum3, 2)[1:]
		nowlong := 32 - len(sum3S)
		for i := 0; i < nowlong; i++ {
			sum3S = "0" + sum3S
		}
	} else {
		sum3 += int64(b4) << 16
		sum3 += int64(b5)
		sum3S = strconv.FormatInt(sum3, 2)
		nowlong := 32 - len(sum3S)
		for i := 0; i < nowlong; i++ {
			sum3S = "0" + sum3S
		}
	}

	if b0 == 0 {
		sum4 += int64(b6) + 1<<16
		sum4 += int64(b7)
		sum4S = strconv.FormatInt(sum4, 2)[1:]
		nowlong := 32 - len(sum4S)
		for i := 0; i < nowlong; i++ {
			sum4S = "0" + sum4S
		}
	} else {
		sum4 += int64(b6) << 16
		sum4 += int64(b7)
		sum4S = strconv.FormatInt(sum4, 2)
		nowlong := 32 - len(sum4S)
		for i := 0; i < nowlong; i++ {
			sum4S = "0" + sum4S
		}
	}
	// log.Println(sum1S, len(sum1S))
	// log.Println(sum2S, len(sum2S))
	// log.Println(sum3S, len(sum3S))
	// log.Println(sum4S, len(sum4S))

	return sum1S + sum2S + sum3S + sum4S
}

func main() {
	// cidrMatch, _ := NewCidrMatch("cn_rules.conf")
	// ip, err := net.LookupIP("www.baidu.com")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// if len(ip) == 0 {
	// 	log.Println(ip, "no host")
	// 	return
	// }
	// log.Println(cidrMatch.Match(ip[0]))
}
