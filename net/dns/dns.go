package dns

import (
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/net/common"
	"math/rand"
	"net"
	"strings"
	"time"
)

type reqType [2]byte

var (
	A     = reqType{0b00000000, 0b00000001} // 1
	NS    = reqType{0b00000000, 0b00000010} // 2
	CNAME = reqType{0b00000000, 0b00000101} // 5
	SOA   = reqType{0b00000000, 0b00000110} // 6
	WKS   = reqType{0b00000000, 0b00001011} // 11
	PTR   = reqType{0b00000000, 0b00001100} // 12
	HINFO = reqType{0b00000000, 0b00001101} // 13
	MX    = reqType{0b00000000, 0b00001111} // 15
	AAAA  = reqType{0b00000000, 0b00011100} // 28
	AXFR  = reqType{0b00000000, 0b11111100} // 252
	ANY   = reqType{0b00000000, 0b11111111} // 255
)

// DNS <-- dns
func DNS(DNSServer, domain string) (DNS []net.IP, err error) {
	req := creatRequest(domain, A)
	var b = common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(b[:cap(b)])

	conn, err := net.DialTimeout("udp", DNSServer, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = conn.Write(req); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(b[:])
	if err != nil {
		return nil, err
	}

	// resolve answer
	anCount, c, err := resolveHeader(req, b[:n])
	if err != nil {
		return nil, err
	}

	//log.Println()
	//log.Println("Answer section:")

	//var x string
	for anCount != 0 {
		_, c = getName(c, b[:n])
		//log.Println(x)

		tYPE := reqType{c[0], c[1]}
		//log.Println("type:", c[0], c[1])
		c = c[2:] // type
		//log.Println("class:", c[0], c[1])
		c = c[2:] // class
		//log.Println("ttl:", c[0], c[1], c[2], c[3])
		c = c[4:] // ttl 4byte
		sum := int(c[0])<<8 + int(c[1])
		//log.Println("rdlength", sum)
		c = c[2:] // RDLENGTH  跳过总和，因为总和不包括计算域名的长度 2+int(c[0])<<8+int(c[1])

		switch tYPE {
		case A:
			DNS = append(DNS, c[0:4])
			c = c[4:] // 4 byte ip addr
		case AAAA:
			DNS = append(DNS, c[0:16])
			c = c[16:] // 16 byte ip addr
		case CNAME:
			fallthrough
		case SOA:
			fallthrough
		case NS:
			fallthrough
		case WKS:
			fallthrough
		case PTR:
			fallthrough
		case HINFO:
			fallthrough
		case MX:
			fallthrough
		default:
			//log.Println("rdata", c[:sum])
			c = c[sum:] // RDATA
		}
		anCount -= 1
	}

	return DNS, nil
}

func creatRequest(domain string, reqType reqType) []byte {
	id := []byte{byte(rand.Intn(255 - 0)), byte(rand.Intn(255 - 0))}                                  // id:
	qr2rd := byte(0b00000001)                                                                         // qr: 0 opcode: 0000 aa: 0 tc: 0 rd: 1 => bit: 00000001 -> 1
	ra2rCode := byte(0b00000000)                                                                      // ra: 0 z:000 rcode: 0000 => bit: 00000000 -> 0
	qdCount := []byte{0b00000000, 0b00000001}                                                         // request number => bit: 00000000 00000001 -> 01
	anCount2arCount := []byte{0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000} // answer number(no use for req) => bit: 00000000 00000000 00000000 00000000 00000000 00000000 -> 000000
	req := append(id, qr2rd, ra2rCode, qdCount[0], qdCount[1])
	req = append(req, anCount2arCount...)

	//var domainSet []byte
	divDomain := strings.Split(domain, ".")
	for index := range divDomain {
		one := append([]byte{byte(len(divDomain[index]))}, []byte(divDomain[index])...)
		req = append(req, one...)
	}
	req = append(req, 0b00000000) // add the 0 for last of domain

	qType := []byte{reqType[0], reqType[1]}  // type: 1 -> A:ipv4 01 | 28 -> AAAA:ipv6  000000 00011100 => 0 0x1c
	qClass := []byte{0b00000000, 0b00000001} // 1 -> from internet
	req = append(req, qType...)
	req = append(req, qClass...)
	return req
}

func resolveHeader(req []byte, answer []byte) (anCount int, answerSection []byte, err error) {
	// resolve answer
	idA := []byte{answer[0], answer[1]}
	if idA[0] != req[0] || idA[1] != req[1] { // id: req[0] req[1]
		// not the answer
		return 0, nil, errors.New("id not same")
	}
	qr2rdA := answer[2]

	if qr2rdA&8 != 0 {
		// not the answer "the qr is not 1", qr2rdA, qr2rdA&8
		return 0, nil, errors.New("the qr is not 1")
	}
	ra2rCodeA := answer[3]
	//qdCountA := []byte{b[4], b[5]}  // no use, for request
	anCountA := []byte{answer[6], answer[7]}
	//nsCount2arCountA := []byte{b[8], b[9], b[10], b[11]} // no use

	rCode := fmt.Sprintf("%08b", ra2rCodeA)[4:]
	switch rCode {
	case "0000":
		break
	case "0001":
		return 0, nil, errors.New("request format error")
	case "0010":
		return 0, nil, errors.New("dns server error")
	case "0011":
		return 0, nil, errors.New("no such name")
	case "0100":
		return 0, nil, errors.New("dns server not support this request")
	case "0101":
		return 0, nil, errors.New("dns server Refuse")
	default:
		return 0, nil, errors.New("other error")
	}

	c := answer[12:]
	anCount = int(anCountA[0])<<8 + int(anCountA[1])
	//log.Println("anCount", anCount)

	//log.Println()
	//log.Println("Question section:")
	//var x string
	_, c = getName(c, answer)
	//log.Println(x)
	c = c[1:] // lastOfDomain: one byte 0
	//log.Println("qType:", c[:2])
	c = c[2:]
	//log.Println("qClass:", c[:2])
	c = c[2:]

	return anCount, c, nil
}

func getName(c []byte, all []byte) (name string, x []byte) {
	for {
		if c[0]&128 == 128 && c[0]&64 == 64 {
			l := c[1]
			c = c[2:]
			tmp, _ := getName(all[l:], all)
			name += tmp
			//log.Println(c, name)
			break
		}
		name += string(c[1:int(c[0])+1]) + "."
		c = c[int(c[0])+1:]
		if c[0] == 0 {
			break
		}
	}
	return name, c
}

/*
+------------------------------+
|             id               |  16bit
+------------------------------+
|qr|opcpde|aa|tc|rd|ra|z|rcode |
+------------------------------+
|          QDCOUNT             |
+------------------------------+
|          ancount             |
+------------------------------+
|          nscount             |
+------------------------------+
|          arcount             |
+------------------------------+

• ID：这是由生成DNS查询的程序指定的16位的标志符。
该标志符也被随后的应答报文所用，
	申请者利用这个标志将应答和原来的请求对应起来。

• QR：该字段占1位，用以指明DNS报文是请求（0）还是应答（1）。
• OPCODE：该字段占4位，用于指定查询的类型。
	值为0表示标准查询，值为1表示逆向查询，值为2表示查询服务器状态，
	值为3保留，值为4表示通知，值为5表示更新报文，值6～15的留为新增操作用。

• AA：该字段占1位，仅当应答时才设置。
	值为1，即意味着正应答的域名服务器是所查询域名的
	管理机构或者说是被授权的域名服务器。

• TC：该字段占1位，代表截断标志。
	如果报文长度比传输通道所允许的长而被分段，该位被设为1。

• RD：该字段占1位，是可选项，表示要求递归与否。
	如果为1，即意味 DNS解释器要求DNS服务器使用递归查询。

• RA：该字段占1位，代表正在应答的域名服务器可以执行递归查询，
	该字段与查询段无关。
• Z：该字段占3位，保留字段，其值在查询和应答时必须为0。
• RCODE：该字段占4位，该字段仅在DNS应答时才设置。用以指明是否发生了错误。
允许取值范围及意义如下：
0：无错误情况，DNS应答表现为无错误。
1：格式错误，DNS服务器不能解释应答。
2：严重失败，因为名字服务器上发生了一个错误，DNS服务器不能处理查询。
3：名字错误，如果DNS应答来自于授权的域名服务器，
	意味着DNS请求中提到的名字不存在。
4：没有实现。DNS服务器不支持这种DNS请求报文。
5：拒绝，由于安全或策略上的设置问题，DNS名字服务器拒绝处理请求。
6 ～15 ：留为后用。

• QDCOUNT：该字段占16位，指明DNS查询段中的查询问题的数量。
• ANCOUNT：该字段占16位，指明DNS应答段中返回的资源记录的数量，在查询段中该值为0。
• NSCOUNT：该字段占16位，指明DNS应答段中所包括的授权域名服务器的资源记录的数量，在查询段中该值为0。
• ARCOUNT：该字段占16位，指明附加段里所含资源记录的数量，在查询段中该值为0。
(2）DNS正文段
在DNS报文中，其正文段封装在图7-42所示的DNS报文头内。DNS有四类正文段：查询段、应答段、授权段和附加段。
*/
