package dns

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/net/utils"
)

type DNS interface {
	SetProxy(proxy func(addr string) (net.Conn, error))
	SetServer(host string)
	GetServer() string
	SetSubnet(subnet *net.IPNet)
	GetSubnet() *net.IPNet
	Search(domain string) ([]net.IP, error)
}

type reqType [2]byte

var (
	A     = reqType{0b00000000, 0b00000001} // 1
	NS    = reqType{0b00000000, 0b00000010} // 2
	MD    = reqType{0b00000000, 0b00000011} // 3
	MF    = reqType{0b00000000, 0b00000100} // 3
	CNAME = reqType{0b00000000, 0b00000101} // 5
	SOA   = reqType{0b00000000, 0b00000110} // 6
	MB    = reqType{0b00000000, 0b00000111} // 7
	MG    = reqType{0b00000000, 0b00001000} // 8
	MR    = reqType{0b00000000, 0b00001001} // 9
	NULL  = reqType{0b00000000, 0b00001010} // 10
	WKS   = reqType{0b00000000, 0b00001011} // 11
	PTR   = reqType{0b00000000, 0b00001100} // 12
	HINFO = reqType{0b00000000, 0b00001101} // 13
	MINFO = reqType{0b00000000, 0b00001110} // 14
	MX    = reqType{0b00000000, 0b00001111} // 15
	TXT   = reqType{0b00000000, 0b00010000} // 16
	AAAA  = reqType{0b00000000, 0b00011100} // 28 https://www.ietf.org/rfc/rfc3596.txt
	RRSIG = reqType{0b00000000, 0b00101110} // 46 dnssec
	// for req
	AXFR = reqType{0b00000000, 0b11111100} // 252
	ANY  = reqType{0b00000000, 0b11111111} // 255
)

type NormalDNS struct {
	DNS
	Server string
	Subnet *net.IPNet
	cache  *utils.LRU
}

func NewNormalDNS(host string) DNS {
	_, subnet, _ := net.ParseCIDR("0.0.0.0/0")
	return &NormalDNS{
		Server: host,
		Subnet: subnet,
		cache:  utils.NewLru(200, 20*time.Minute),
	}
}

// DNS Normal DNS(use udp,and no encrypt)
func (n *NormalDNS) Search(domain string) (DNS []net.IP, err error) {
	if x := n.cache.Load(domain); x != nil {
		return x.([]net.IP), nil
	}
	DNS, err = dnsCommon(domain, n.Subnet, func(data []byte) ([]byte, error) { return udpDial(data, n.Server) })
	if err != nil || len(DNS) == 0 {
		return nil, fmt.Errorf("normal resolve domain %s failed: %v", domain, err)
	}
	n.cache.Add(domain, DNS)
	return
}

func (n *NormalDNS) SetSubnet(ip *net.IPNet) {
	if ip == nil {
		_, n.Subnet, _ = net.ParseCIDR("0.0.0.0/0")
		return
	}
	if ip.String() == n.Subnet.String() {
		return
	}
	n.Subnet = ip
}

func (n *NormalDNS) GetSubnet() *net.IPNet {
	return n.Subnet
}

func (n *NormalDNS) SetServer(host string) {
	n.Server = host
}

func (n *NormalDNS) GetServer() string {
	return n.Server
}

func (n *NormalDNS) SetProxy(proxy func(addr string) (net.Conn, error)) {}

func dnsCommon(domain string, subnet *net.IPNet, reqF func(reqData []byte) (body []byte, err error)) (DNS []net.IP, err error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovering from panic in resolve DNS(%s) error is: %v \n", domain, r)
			err = fmt.Errorf("Recovering from panic in resolve DNS(%s) error is: %v \n", domain, r)
		}
	}()
	req := createEDNSReq(domain, A, createEdnsClientSubnet(subnet))

	b, err := reqF(req)
	if err != nil {
		return nil, err
	}

	// resolve answer
	h, c, err := resolveHeader(req, b)
	if err != nil {
		return nil, err
	}
	DNS, c, err = resolveAnswer(c, h.anCount, b)
	c = resolveAuthoritative(c, h.nsCount, b)
	resolveAdditional(c, h.arCount) // EDNS
	return
}

func udpDial(req []byte, DNSServer string) (data []byte, err error) {
	var b = utils.BuffPool.Get().([]byte)
	defer utils.BuffPool.Put(b)

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
	return b[:n], nil
}

func creatRequest(domain string, reqType reqType, arCount bool) []byte {
	data := bytes.NewBuffer(nil)
	data.Write([]byte{byte(rand.Intn(255)), byte(rand.Intn(255))}) // id
	// qr 0, opcode 0000, aa 0, tc 0, rd 1 => 1 byte, ra 0, z 000, rCode 0000 => 1 byte
	data.Write([]byte{0b0<<7 + 0b0000<<3 + 0b0<<2 + 0b0<<1 + 0b1, 0b0<<7 + 0b000<<4 + 0b0000})
	data.Write([]byte{0b00000000, 0b00000001}) // qdCount: request number => bit: 00000000 00000001 -> 01
	data.Write([]byte{0b00000000, 0b00000000}) // anCount: answer number(no use for req) => bit: 00000000 00000000
	data.Write([]byte{0b00000000, 0b00000000}) // nsCount: authority section 2 bytes
	if arCount {                               // arCount: additional section 2 bytes
		data.Write([]byte{0b00000000, 0b00000001})
	} else {
		data.Write([]byte{0b00000000, 0b00000000})
	}

	for _, x := range strings.Split(domain, ".") { // domain: www.example.com => 3www7example3com <- last with 0
		data.WriteByte(byte(len(x)))
		data.WriteString(x)
	}
	data.WriteByte(0b00000000) // add the 0 for last of domain

	data.Write([]byte{reqType[0], reqType[1]}) // qType 1 -> A:ipv4 01 | 28 -> AAAA:ipv6  000000 00011100 => 0 0x1c
	data.Write([]byte{0b00000000, 0b00000001}) // qClass: 1 = from internet
	//https://www.cnblogs.com/zsy/p/5935407.html
	return data.Bytes()
}

type respHeader struct {
	qdCount int
	anCount int
	nsCount int
	arCount int
	name    string
}

func resolveHeader(req []byte, answer []byte) (header respHeader, answerSection []byte, err error) {
	// resolve answer
	if answer[0] != req[0] || answer[1] != req[1] { // compare id
		// not the answer
		return header, nil, errors.New("id not same")
	}

	if answer[2]&8 != 0 { // check the QR is 1(Answer)
		return header, nil, errors.New("the qr is not 1(Answer)")
	}

	rCode := fmt.Sprintf("%08b", answer[3])[4:] // check Response code(rCode)
	switch rCode {
	case "0000": // no error
		break
	case "0001": // Format error
		return header, nil, errors.New("request format error")
	case "0010": //Server failure
		return header, nil, errors.New("dns Server failure")
	case "0011": //Name Error
		return header, nil, errors.New("no such name")
	case "0100": // Not Implemented
		return header, nil, errors.New("dns server not support this request")
	case "0101": //Refused
		return header, nil, errors.New("dns server Refuse")
	default: // Reserved for future use.
		return header, nil, errors.New("other error")
	}

	header.qdCount = 0                                    // request
	header.anCount = int(answer[6])<<8 + int(answer[7])   // answer Count
	header.nsCount = int(answer[8])<<8 + int(answer[9])   // authority Count
	header.arCount = int(answer[10])<<8 + int(answer[11]) // additional Count

	c := answer[12:]

	header.name, _, c = getName(c, answer)

	c = c[2:] // qType
	c = c[2:] // qClass

	return header, c, nil
}

func resolveAnswer(c []byte, anCount int, b []byte) (DNS []net.IP, left []byte, err error) {
	for anCount != 0 {
		_, _, c = getName(c, b)

		tYPE := reqType{c[0], c[1]}
		c = c[2:] // type
		c = c[2:] // class
		c = c[4:] // ttl 4byte
		sum := int(c[0])<<8 + int(c[1])
		c = c[2:] // RDLENGTH  jump sum 2+int(c[0])<<8+int(c[1])

		switch tYPE {
		case A:
			DNS = append(DNS, c[0:4])
			c = c[4:] // 4 byte ip addr
		case AAAA:
			DNS = append(DNS, c[0:16])
			c = c[16:] // 16 byte ip addr
		case RRSIG:
			typeCover := c[:2]
			c = c[2:]
			algorithm := c[:1]
			c = c[1:]
			label := c[:1]
			c = c[1:]
			originalTTL := c[:4]
			c = c[4:]
			signExpiration := c[:4]
			c = c[4:]
			signInception := c[:4]
			c = c[4:]
			keyTag := c[:2]
			c = c[2:]
			signName, size, others := getName(c, b)
			c = others
			signature := c[:sum-size-18]
			c = c[sum-size-18:]
			log.Println(typeCover, algorithm, label, originalTTL, signExpiration, signInception, keyTag, signName, signature)
			break
		case NS, MD, MF, CNAME, SOA, MG, MB, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT:
			fallthrough
		default:
			c = c[sum:] // RDATA
		}
		anCount--
	}
	return DNS, c, nil
}

func resolveAuthoritative(c []byte, nsCount int, b []byte) (left []byte) {
	for nsCount != 0 {
		nsCount--
		_, _, c = getName(c, b)
		c = c[2:] // type
		c = c[2:] // class
		c = c[4:] // ttl
		dataLength := int(c[0])<<8 + int(c[1])
		c = c[2:] // data length
		c = c[dataLength:]
	}
	return c
}

func getName(c []byte, all []byte) (name string, size int, x []byte) {
	s := strings.Builder{}
	for {
		if c[0] == 0 {
			c = c[1:] // lastOfDomain: one byte 0
			size++
			break
		}
		if c[0]&128 == 128 && c[0]&64 == 64 {
			l := c[1]
			c = c[2:]
			size += 2
			tmp, _, _ := getName(all[l:], all)
			s.WriteString(tmp)
			break
		}
		s.Write(c[1 : int(c[0])+1])
		s.WriteString(".")
		size += int(c[0]) + 1
		c = c[int(c[0])+1:]
	}
	return s.String(), size, c
}

// https://www.ietf.org/rfc/rfc1035.txt
/*
4.1.1. Header section format

The header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

ID              A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).
OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:
                0               a standard query (QUERY)
                1               an inverse query (IQUERY)
                2               a server status request (STATUS)
                3-15            reserved for future use
AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.
                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit



Mockapetris                                                    [Page 26]

RFC 1035        Domain Implementation and Specification    November 1987


                corresponds to the name which matches the query name, or
                the first owner name in the answer section.

TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
Z               Reserved for future use.  Must be zero in all queries
                and responses.
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:
                0               No error condition
                1               Format error - The name server was
                                unable to interpret the query.
                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.
                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.
                4               Not Implemented - The name server does
                                not support the requested kind of query.
                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone


Mockapetris                                                    [Page 27]

RFC 1035        Domain Implementation and Specification    November 1987


                                transfer) for particular data.
                6-15            Reserved for future use.

QDCOUNT         an unsigned 16 bit integer specifying the number of
                entries in the question section.
ANCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the answer section.
NSCOUNT         an unsigned 16 bit integer specifying the number of name
                server resource records in the authority records
                section.
ARCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the additional records section.


4.1.2. Question section format

The question section is used to carry the "question" in most queries,
i.e., the parameters that define what is being asked.  The section
contains QDCOUNT (usually 1) entries, each of the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

QNAME           a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used.
QTYPE           a two octet code which specifies the type of the query.
                The values for this field include all codes valid for a
                TYPE field, together with some more general codes which
                can match more than one type of RR.



Mockapetris                                                    [Page 28]

RFC 1035        Domain Implementation and Specification    November 1987


QCLASS          a two octet code that specifies the class of the query.
                For example, the QCLASS field is IN for the Internet.
*/

/*
4.1.3. Resource record format

The answer, authority, and additional sections all share the same
format: a variable number of resource records, where the number of
records is specified in the corresponding count field in the header.
Each resource record has the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


where:
NAME            an owner name, i.e., the name of the node to which this
                resource record pertains.
TYPE            two octets containing one of the RR TYPE codes.
CLASS           two octets containing one of the RR CLASS codes.
TTL             a 32 bit signed integer that specifies the time interval
                that the resource record may be cached before the source
                of the information should again be consulted.  Zero
                values are interpreted to mean that the RR can only be
                used for the transaction in progress, and should not be
                cached.  For example, SOA records are always distributed
                with a zero TTL to prohibit caching.  Zero values can
                also be used for extremely volatile data.
RDLENGTH        an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.

Mockapetris                                                    [Page 11]

RFC 1035        Domain Implementation and Specification    November 1987

RDATA           a variable length string of octets that describes the
                resource.  The format of this information varies
                according to the TYPE and CLASS of the resource record.

3.2.2. TYPE values

TYPE fields are used in resource records.  Note that these types are a
subset of QTYPEs.

TYPE            value and meaning
A               1 a host address
NS              2 an authoritative name server
MD              3 a mail destination (Obsolete - use MX)
MF              4 a mail forwarder (Obsolete - use MX)
CNAME           5 the canonical name for an alias
SOA             6 marks the start of a zone of authority
MB              7 a mailbox domain name (EXPERIMENTAL)
MG              8 a mail group member (EXPERIMENTAL)
MR              9 a mail rename domain name (EXPERIMENTAL)
NULL            10 a null RR (EXPERIMENTAL)
WKS             11 a well known service description
PTR             12 a domain name pointer
HINFO           13 host information
MINFO           14 mailbox or mail list information
MX              15 mail exchange
TXT             16 text strings
*/
