package socks5server

import (
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"

	"../cidrmatch"
	"../socks5ToHttp"
)

// ServerSocks5 <--
type ServerSocks5 struct {
	Server             string
	Port               string
	conn               net.Listener
	ToHTTP             bool
	HTTPServer         string
	HTTPPort           string
	Username           string
	Password           string
	ToShadowsocksr     bool
	ShadowsocksrServer string
	ShadowsocksrPort   string
	Socks5Server       string
	Socks5Port         string
	Bypass             bool
	cidrmatch          *cidrmatch.CidrMatch
	CidrFile           string
}

// Socks5 <--
func (socks5Server *ServerSocks5) Socks5() error {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	var err error
	socks5Server.cidrmatch, err = cidrmatch.NewCidrMatchWithMap(socks5Server.CidrFile)
	if err != nil {
		return err
	}
	socks5Server.conn, err = net.Listen("tcp", socks5Server.Server+":"+socks5Server.Port)
	if err != nil {
		// log.Panic(err)
		return err
	}

	for {
		client, err := socks5Server.conn.Accept()
		if err != nil {
			// log.Panic(err)
			return err
		}

		go func() {
			log.Println(runtime.NumGoroutine())
			if client == nil {
				return
			}
			defer client.Close()
			socks5Server.handleClientRequest(client)
		}()
	}
}

func (socks5Server *ServerSocks5) handleClientRequest(client net.Conn) {

	var b [1024]byte
	_, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}

	if b[0] == 0x05 { //只处理Socks5协议
		client.Write([]byte{0x05, 0x00})
		if b[1] == 0x01 {
			// 对用户名密码进行判断
			if b[2] == 0x02 {
				_, err = client.Read(b[:])
				if err != nil {
					log.Println(err)
					return
				}
				username := b[2 : 2+b[1]]
				password := b[3+b[1] : 3+b[1]+b[2+b[1]]]
				if socks5Server.Username == string(username) && socks5Server.Password == string(password) {
					client.Write([]byte{0x01, 0x00})
				} else {
					client.Write([]byte{0x01, 0x01})
					return
				}
			}
		}

		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}

		var host, port, hostTemplate string
		switch b[3] {
		case 0x01: //IP V4
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
			hostTemplate = "ip"
		case 0x03: //域名
			host = string(b[5 : n-2]) //b[4]表示域名的长度
			hostTemplate = "domain"
		case 0x04: //IP V6
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
			hostTemplate = "ip"
		}
		port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))

		if b[1] == 0x01 {
			log.Println("connect 请求 " + net.JoinHostPort(host, port))
			if socks5Server.Bypass == true {
				if socks5Server.ToHTTP == true {
					var isMatched bool
					if hostTemplate != "ip" {
						ip, err := net.LookupHost(host)
						if err != nil {
							log.Println(err)
							// return
							isMatched = false
						} else {
							if len(ip) == 0 {
								isMatched = false
							} else {
								isMatched = socks5Server.cidrmatch.MatchWithMap(ip[0])
							}
						}
					} else {
						isMatched = socks5Server.cidrmatch.MatchWithMap(host)
					}

					log.Println("isMatched", isMatched)
					if isMatched == false {
						socks5Server.toHTTP(client, host, port)
					} else {
						socks5Server.toTCP(client, net.JoinHostPort(host, port))
					}
				} else if socks5Server.ToShadowsocksr == true {
					var isMatched bool
					if hostTemplate != "ip" {
						ip, err := net.LookupHost(host)
						if err != nil {
							log.Println(err)
							// return
							isMatched = false
						} else {
							if len(ip) == 0 {
								isMatched = false
							} else {
								isMatched = socks5Server.cidrmatch.MatchWithMap(ip[0])
							}
						}
					} else {
						isMatched = socks5Server.cidrmatch.MatchWithMap(host)
					}

					log.Println("isMatched", isMatched)
					if isMatched == false {
						socks5Server.toSocks5(client, net.JoinHostPort(host, port), b[:n])
					} else {
						socks5Server.toTCP(client, net.JoinHostPort(host, port))
					}
				}
			} else {
				if socks5Server.ToHTTP == true {
					socks5Server.toHTTP(client, host, port)
				} else if socks5Server.ToShadowsocksr == true {
					socks5Server.toSocks5(client, net.JoinHostPort(host, port), b[:n])
				} else {
					socks5Server.toTCP(client, net.JoinHostPort(host, port))
				}
			}
		} else if b[1] == 0x02 {
			log.Println("bind 请求 " + net.JoinHostPort(host, port))
		} else if b[1] == 0x03 {
			log.Println("udp 请求 " + net.JoinHostPort(host, port))
			socks5Server.udp(client, net.JoinHostPort(host, port))
		}
	} else {
		// do something
		return
	}

}

func (socks5Server *ServerSocks5) connect() {
	// do something
}

func (socks5Server *ServerSocks5) udp(client net.Conn, domain string) {
	// log.Println()
	server, err := net.Dial("udp", domain)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //响应客户端连接成功
	//进行转发
	// httpConnect := make([]byte, 1024)
	// n, _ := client.Read(httpConnect[:])
	// log.Println(string(httpConnect))
	// server.Write(httpConnect[:n])
	go io.Copy(server, client)
	io.Copy(client, server)

}

func (socks5Server *ServerSocks5) toTCP(client net.Conn, domain string) {
	server, err := net.Dial("tcp", domain)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //响应客户端连接成功
	//进行转发
	// httpConnect := make([]byte, 1024)
	// n, _ := client.Read(httpConnect[:])
	// log.Println(string(httpConnect))
	// server.Write(httpConnect[:n])
	go io.Copy(server, client)
	io.Copy(client, server)
}

func (socks5Server *ServerSocks5) toHTTP(client net.Conn, host, port string) {
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //响应客户端连接成功
	server, err := net.Dial("tcp", socks5Server.HTTPServer+":"+socks5Server.HTTPPort)
	if err != nil {
		log.Println(err)
	}
	defer server.Close()
	// if port == "443" {
	server.Write([]byte("CONNECT " + host + ":" + port + " HTTP/1.1\r\n\r\n"))
	httpConnect := make([]byte, 1024)
	server.Read(httpConnect[:])
	log.Println(string(httpConnect))
	// }
	// n, _ := client.Read(httpConnect[:])
	// log.Println(string(httpConnect))
	// server.Write(httpConnect[:n])
	go io.Copy(server, client)
	io.Copy(client, server)
}

func (socks5Server *ServerSocks5) toShadowsocksr(client net.Conn) {
	server, err := net.Dial("tcp", socks5Server.ShadowsocksrServer+":"+socks5Server.ShadowsocksrPort)
	if err != nil {
		log.Println(err)
	}
	defer server.Close()
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //响应客户端连接成功
	// 转发
	// httpConnect := make([]byte, 1024)
	// n, _ := client.Read(httpConnect[:])
	// log.Println(string(httpConnect))
	// server.Write(httpConnect[:n])
	go io.Copy(server, client)
	io.Copy(client, server)
}

func (socks5Server *ServerSocks5) toSocks5(client net.Conn, host string, b []byte) {
	socks5Conn, err := (&socks5ToHttp.Socks5Client{
		Server:  socks5Server.Socks5Server,
		Port:    socks5Server.Socks5Port,
		Address: host}).NewSocks5ClientOnlyFirstVerify()
	if err != nil {
		log.Println(err)
	}

	defer socks5Conn.Close()
	socks5Conn.Write(b)
	// client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //响应客户端连接成功
	// 转发
	// httpConnect := make([]byte, 1024)
	// n, _ := client.Read(httpConnect[:])
	// log.Println(string(httpConnect))
	// server.Write(httpConnect[:n])

	go io.Copy(client, socks5Conn)
	io.Copy(socks5Conn, client)
}

func dns() {
	// +------------------------------+
	// |             id               |
	// +------------------------------+
	// |qr|opcpde|aa|tc|rd|ra|z|rcode |
	// +------------------------------+
	// |          QDCOUNT             |
	// +------------------------------+
	// |          ancount             |
	// +------------------------------+
	// |          nscount             |
	// +------------------------------+
	// |          arcount             |
	// +------------------------------+
	// • ID：这是由生成DNS查询的程序指定的16位的标志符。该标志符也被随后的应答报文所用，申请者利用这个标志将应答和原来的请求对应起来。
	// • QR：该字段占1位，用以指明DNS报文是请求（0）还是应答（1）。
	// • OPCODE：该字段占4位，用于指定查询的类型。值为0表示标准查询，值为1表示逆向查询，值为2表示查询服务器状态，值为3保留，值为4表示通知，值为5表示更新报文，值6～15的留为新增操作用。
	// • AA：该字段占1位，仅当应答时才设置。值为1，即意味着正应答的域名服务器是所查询域名的管理机构或者说是被授权的域名服务器。
	// • TC：该字段占1位，代表截断标志。如果报文长度比传输通道所允许的长而被分段，该位被设为1。
	// • RD：该字段占1位，是可选项，表示要求递归与否。如果为1，即意味 DNS解释器要求DNS服务器使用递归查询。
	// • RA：该字段占1位，代表正在应答的域名服务器可以执行递归查询，该字段与查询段无关。
	// • Z：该字段占3位，保留字段，其值在查询和应答时必须为0。
	// • RCODE：该字段占4位，该字段仅在DNS应答时才设置。用以指明是否发生了错误。
	// 允许取值范围及意义如下：
	// 0：无错误情况，DNS应答表现为无错误。
	// 1：格式错误，DNS服务器不能解释应答。
	// 2：严重失败，因为名字服务器上发生了一个错误，DNS服务器不能处理查询。
	// 3：名字错误，如果DNS应答来自于授权的域名服务器，意味着DNS请求中提到的名字不存在。
	// 4：没有实现。DNS服务器不支持这种DNS请求报文。
	// 5：拒绝，由于安全或策略上的设置问题，DNS名字服务器拒绝处理请求。
	// 6 ～15 ：留为后用。
	// • QDCOUNT：该字段占16位，指明DNS查询段中的查询问题的数量。
	// • ANCOUNT：该字段占16位，指明DNS应答段中返回的资源记录的数量，在查询段中该值为0。
	// • NSCOUNT：该字段占16位，指明DNS应答段中所包括的授权域名服务器的资源记录的数量，在查询段中该值为0。
	// • ARCOUNT：该字段占16位，指明附加段里所含资源记录的数量，在查询段中该值为0。
	// (2）DNS正文段
	// 在DNS报文中，其正文段封装在图7-42所示的DNS报文头内。DNS有四类正文段：查询段、应答段、授权段和附加段。

	// id := make([]byte, 16)
	id := []byte("test")
	qr := byte(0x00)
	qopcode := []byte{0x00, 0x00, 0x00, 0x00}
	aa := byte(0x00)
	tc := byte(0x00)
	rd := byte(0x01)
	ra := byte(0x00)
	z := []byte{0x00, 0x00, 0x00}
	rcode := []byte{0x00, 0x00, 0x00, 0x00}
	qdcount := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	ancount := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	nscount := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	arcount := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	domain := "www.baidu.com"
	domainSplit := strings.Split(domain, ".")
	var domainSet string
	for _, domain := range domainSplit {
		domainSet += strconv.Itoa(len(domain)) + domain
	}
	domainSets := []byte(domainSet)
	qtype := []byte("A")
	qclass := []byte("inet")

	all := append(id, qr)
	all = append(all, qopcode...)
	all = append(all, aa, tc, rd, ra)
	all = append(all, z...)
	all = append(all, rcode...)
	all = append(all, qdcount...)
	all = append(all, ancount...)
	all = append(all, nscount...)
	all = append(all, arcount...)
	all = append(all, domainSets...)
	all = append(all, qtype...)
	all = append(all, qclass...)
	log.Println(string(all))
}
