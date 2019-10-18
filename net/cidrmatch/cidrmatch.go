package cidrmatch

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"

	"SsrMicroClient/microlog"
	"SsrMicroClient/net/cidrmatch/trie"
)

// CidrMatch <--
type CidrMatch struct {
	maskSize   int
	v4CidrTrie *trie.TrieTree
	v6CidrTrie *trie.TrieTree
	cidrMap    map[string][]*net.IPNet
	cidrS      []*net.IPNet
}

// NewCidrMatchWithTrie <--
func NewCidrMatchWithTrie(fileName string) (*CidrMatch, error) {
	microlog.Debug("cidrFileName", fileName)
	cidrMatch := new(CidrMatch)
	cidrMatch.v4CidrTrie = trie.NewTrieTree()
	cidrMatch.v6CidrTrie = trie.NewTrieTree()
	cidrMatch.insertCidrTrie(fileName)
	return cidrMatch, nil
}

func (cidrMatch *CidrMatch) insertCidrTrie(fileName string) {
	configTemp, _ := ioutil.ReadFile(fileName)
	for _, cidr := range strings.Split(string(configTemp), "\n") {
		if err := cidrMatch.InsetOneCIDR(cidr); err != nil {
			continue
		}
	}
}

// InsetOneCIDR Insert one CIDR to cidr matcher
func (cidrMatch *CidrMatch) InsetOneCIDR(cidr string) error {
	defer func() { //必须要先声明defer，否则不能捕获到panic异常
		if err := recover(); err != nil {
			microlog.Debug(err)
		}
	}()
	ipAndMask := strings.Split(cidr, "/")
	maskSize, err := strconv.Atoi(ipAndMask[1])
	if err != nil {
		return err
	}
	/* 十进制转化为二进制 */
	c := ""
	if net.ParseIP(ipAndMask[0]) != nil {
		if net.ParseIP(ipAndMask[0]).To4() != nil {
			c = IpAddrToInt(ipAndMask[0])
			cidrMatch.v4CidrTrie.Insert(c[:maskSize])
		} else {
			c = Ipv6AddrToInt(ToIpv6(ipAndMask[0]))
			cidrMatch.v6CidrTrie.Insert(c[:maskSize])
		}
	} else {
		//	do something
		return errors.New("this cidr don't have ip")
	}
	return nil
}

// MatchWithTrie match ip with trie
func (cidrMatch *CidrMatch) MatchWithTrie(ip string) bool {
	ipTmp := net.ParseIP(ip)
	ipBinary := ""
	if ipTmp.To4() != nil {
		ipBinary = IpAddrToInt(ip)
		return cidrMatch.v4CidrTrie.Search(ipBinary)
	} else if ipTmp.To16() != nil {
		ipBinary = Ipv6AddrToInt(ToIpv6(ip))
		return cidrMatch.v6CidrTrie.Search(ipBinary)
	}
	return false
}

// IpAddrToInt convert ipv4 to binary
func IpAddrToInt(ipAddr string) string {
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
	nowLong := 32 - len(c)
	for i := 0; i < nowLong; i++ {
		c = "0" + c
	}
	return c
}

// ToIpv6 convert ipv6 to completely ip
func ToIpv6(ip string) string {
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
		needZero = 8 - len(strings.Split(ipv6b1, ":")) -
			len(strings.Split(ipv6b2, ":"))
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

// Ipv6AddrToInt convert ipv6 to binary
func Ipv6AddrToInt(ipAddr string) string {
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
		sum1 += b0 + 1<<16
		sum1 += b1
		sum1S = strconv.FormatInt(sum1, 2)[1:]
		nowLong := 32 - len(sum1S)
		for i := 0; i < nowLong; i++ {
			sum1S = "0" + sum1S
		}
	} else {
		sum1 += b0 << 16
		sum1 += b1
		sum1S = strconv.FormatInt(sum1, 2)
		log.Println(sum1S)
		nowLong := 32 - len(sum1S)
		for i := 0; i < nowLong; i++ {
			sum1S = "0" + sum1S
		}
	}

	if b0 == 0 {
		sum2 += b2 + 1<<16
		sum2 += b3
		sum2S = strconv.FormatInt(sum2, 2)[1:]
		nowLong := 32 - len(sum2S)
		for i := 0; i < nowLong; i++ {
			sum2S = "0" + sum2S
		}
	} else {
		sum2 += b2 << 16
		sum2 += b3
		sum2S = strconv.FormatInt(sum2, 2)
		nowLong := 32 - len(sum2S)
		for i := 0; i < nowLong; i++ {
			sum2S = "0" + sum2S
		}
	}

	if b0 == 0 {
		sum3 += b4 + 1<<16
		sum3 += b5
		sum3S = strconv.FormatInt(sum3, 2)[1:]
		nowLong := 32 - len(sum3S)
		for i := 0; i < nowLong; i++ {
			sum3S = "0" + sum3S
		}
	} else {
		sum3 += b4 << 16
		sum3 += b5
		sum3S = strconv.FormatInt(sum3, 2)
		nowLong := 32 - len(sum3S)
		for i := 0; i < nowLong; i++ {
			sum3S = "0" + sum3S
		}
	}

	if b0 == 0 {
		sum4 += b6 + 1<<16
		sum4 += b7
		sum4S = strconv.FormatInt(sum4, 2)[1:]
		nowLong := 32 - len(sum4S)
		for i := 0; i < nowLong; i++ {
			sum4S = "0" + sum4S
		}
	} else {
		sum4 += b6 << 16
		sum4 += b7
		sum4S = strconv.FormatInt(sum4, 2)
		nowLong := 32 - len(sum4S)
		for i := 0; i < nowLong; i++ {
			sum4S = "0" + sum4S
		}
	}
	// log.Println(sum1S, len(sum1S))
	// log.Println(sum2S, len(sum2S))
	// log.Println(sum3S, len(sum3S))
	// log.Println(sum4S, len(sum4S))

	return sum1S + sum2S + sum3S + sum4S
}

//func _() {
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
//}
