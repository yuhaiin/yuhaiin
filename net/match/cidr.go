package match

import (
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
)

// Cidr cidr matcher
type Cidr struct {
	maskSize   int
	v4CidrTrie *Trie
	v6CidrTrie *Trie
}

// InsetOneCIDR Insert one CIDR to cidr matcher
func (c *Cidr) Insert(cidr, mark string) error {
	defer func() { //必须要先声明defer，否则不能捕获到panic异常
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	ipAndMask := strings.Split(cidr, "/")
	maskSize, err := strconv.Atoi(ipAndMask[1])
	if err != nil {
		return err
	}
	/* 十进制转化为二进制 */
	binary := ""
	if net.ParseIP(ipAndMask[0]) != nil {
		if net.ParseIP(ipAndMask[0]).To4() != nil {
			binary = ipAddrToInt(ipAndMask[0])
			c.v4CidrTrie.Insert(binary[:maskSize], mark)
		} else {
			binary = ipv6AddrToInt(toIpv6(ipAndMask[0]))
			c.v6CidrTrie.Insert(binary[:maskSize], mark)
		}
	} else {
		//	do something
		return errors.New("this cidr don't have ip")
	}
	return nil
}

// MatchWithTrie match ip with trie
func (c *Cidr) Search(ip string) (isMatch bool, mark string) {
	ipTmp := net.ParseIP(ip)
	ipBinary := ""
	if ipTmp.To4() != nil {
		ipBinary = ipAddrToInt(ip)
		return c.v4CidrTrie.Search(ipBinary)
	} else if ipTmp.To16() != nil {
		ipBinary = ipv6AddrToInt(toIpv6(ip))
		return c.v6CidrTrie.Search(ipBinary)
	}
	return false, ""
}

// NewCidrMatchWithTrie <--
func NewCidrMatch() *Cidr {
	cidrMatch := new(Cidr)
	cidrMatch.v4CidrTrie = NewTrieTree()
	cidrMatch.v6CidrTrie = NewTrieTree()
	return cidrMatch
}

/*******************************
	CIDR TRIE
********************************/
// Trie trie tree
type Trie struct {
	root *cidrNode
}

type cidrNode struct {
	isLast bool
	mark   string
	left   *cidrNode
	right  *cidrNode
}

func (t *Trie) Release() {
	t.root.left = nil
	t.root.right = nil
	t.root = nil
}

// Insert insert node to tree
func (t *Trie) Insert(str, mark string) {
	nodeTemp := t.root
	for i := 0; i < len(str); i++ {
		// 1 byte is 49
		if str[i] == 49 {
			if nodeTemp.right == nil {
				nodeTemp.right = new(cidrNode)
			}
			nodeTemp = nodeTemp.right
		}
		// 0 byte is 48
		if str[i] == 48 {
			if nodeTemp.left == nil {
				nodeTemp.left = new(cidrNode)
			}
			nodeTemp = nodeTemp.left
		}
		if i == len(str)-1 {
			nodeTemp.isLast = true
			nodeTemp.mark = mark
		}
	}
}

// Search search from trie tree
func (t *Trie) Search(str string) (isMatch bool, mark string) {
	nodeTemp := t.root
	for i := 0; i < len(str); i++ {
		if str[i] == 49 {
			nodeTemp = nodeTemp.right
		}
		if str[i] == 48 {
			nodeTemp = nodeTemp.left
		}
		if nodeTemp == nil {
			return false, ""
		}
		if nodeTemp.isLast == true {
			return true, nodeTemp.mark
		}
	}
	return false, ""
}

// GetRoot get root node
func (t *Trie) GetRoot() *cidrNode {
	return t.root
}

// PrintTree print this tree
func (t *Trie) PrintTree(node *cidrNode) {
	if node.left != nil {
		t.PrintTree(node.left)
		log.Println("0")
	}
	if node.right != nil {
		t.PrintTree(node.right)
		log.Println("1")
	}
}

// NewTrieTree create a new trie tree
func NewTrieTree() *Trie {
	return &Trie{
		root: &cidrNode{},
	}
}

/**************************************
	OTHERS
***************************************/
// IpAddrToInt convert ipv4 to binary
func ipAddrToInt(ipAddr string) string {
	var str strings.Builder
	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	c := strconv.FormatInt(int64(b0)<<24+int64(b1)<<16+int64(b2)<<8+int64(b3), 2)
	for i := 0; i < 32-len(c); i++ {
		str.WriteByte('0')
	}
	str.WriteString(c)
	return str.String()
}

// toIpv6 convert ipv6 to completely ip
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

// ipv6AddrToInt convert ipv6 to binary
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
		//log.Println(sum1S)
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
