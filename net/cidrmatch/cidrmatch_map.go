package cidrmatch

import (
	"io/ioutil"
	"log"
	"net"
	"strings"

	microlog "../../log"
)

func (cidrMatch *CidrMatch) MatchString(ip string) bool {
	ss := net.ParseIP(ip)
	for _, n := range cidrMatch.cidrS {
		// log.Println(s, n)
		if n.Contains(ss) {
			return true
		}
	}
	return false
}

func (cidrMatch *CidrMatch) Match(ip net.IP) bool {
	for _, n := range cidrMatch.cidrS {
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

// NewCidrMatchWithMap <--
func NewCidrMatchWithMap(fileName string) (*CidrMatch, error) {
	microlog.Debug("cidrfilename", fileName)
	cidrmatch := new(CidrMatch)
	cidrmatch.masksize = cidrmatch.getMaskSize(fileName)
	microlog.Debug("masksize", cidrmatch.masksize)
	cidrmatch.cidrMap = cidrmatch.getCidrMap(fileName)
	microlog.Debug("cidrMapLen", cidrmatch.cidrMap)
	return cidrmatch, nil
}

func (cidrMatch *CidrMatch) getMaskSize(fileName string) int {
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

func (cidrMatch *CidrMatch) getCidrMap(fileName string) map[string][]*net.IPNet {
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
			c = IpAddrToInt(cidr2.IP.String())
		} else {
			c = Ipv6AddrToInt(ToIpv6(cidr2.IP.String()))
		}
		// fmt.Println("c:", c)
		/* 二进制转化为十进制 */
		// d, err := strconv.ParseInt(c, 2, 64)
		// fmt.Println("d:", d, err)
		prefix := c[:cidrMatch.masksize]
		match[prefix] = append(match[prefix], cidr2)
	}
	return match
}

func (cidrMatch *CidrMatch) ipGetKey(ip string) string {
	/* 十进制转化为二进制 */
	ipTmp := net.ParseIP(ip)
	if ipTmp.To4() != nil {
		return IpAddrToInt(ip)[:cidrMatch.masksize]
	} else if ipTmp.To16() != nil {
		return Ipv6AddrToInt(ToIpv6(ip))[:cidrMatch.masksize]
	}
	return ""
}

func (cidrMatch *CidrMatch) MatchWithMap(ip string) bool {
	mapIP := cidrMatch.cidrMap[cidrMatch.ipGetKey(ip)]
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
