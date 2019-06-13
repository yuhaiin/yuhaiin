package socks5ToHttp

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type errErr struct {
	err string
}

func (e errErr) Error() string {
	return fmt.Sprintf(e.err)
}

type socks5client struct {
	conn net.Conn
}

func (socks5client *socks5client) creatDial(server, port string) (net.Conn, error) {
	var err error
	socks5client.conn, err = net.Dial("tcp", server+":"+port)
	if err != nil {
		return socks5client.conn, err
	}
	return socks5client.conn, nil
}

func (socks5client *socks5client) socks5FirstVerify() error {
	// https://tools.ietf.org/html/rfc1928
	// The client connects to the server, and sends a version
	// identifier/method selection message:

	// 				+----+----------+----------+
	// 				|VER | NMETHODS | METHODS  |
	// 				+----+----------+----------+
	// 				| 1  |    1     | 1 to 255 |
	// 				+----+----------+----------+

	// The VER field is set to X'05' for this version of the protocol.  The
	// NMETHODS field contains the number of method identifier octets that
	// appear in the METHODS field.

	// The server selects from one of the methods given in METHODS, and
	// sends a METHOD selection message:

	// 					  +----+--------+
	// 					  |VER | METHOD |
	// 					  +----+--------+
	// 					  | 1  |   1    |
	// 					  +----+--------+

	// If the selected METHOD is X'FF', none of the methods listed by the
	// client are acceptable, and the client MUST close the connection.

	// The values currently defined for METHOD are:

	// 	   o  X'00' NO AUTHENTICATION REQUIRED
	// 	   o  X'01' GSSAPI
	// 	   o  X'02' USERNAME/PASSWORD
	// 	   o  X'03' to X'7F' IANA ASSIGNED
	// 	   o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	// 	   o  X'FF' NO ACCEPTABLE METHODS

	// The client and server then enter a method-specific sub-negotiation.

	//
	//
	// +------------------------------+
	// |	   发送socks5验证信息        |
	// +------------------------------+
	// | socks版本 | 连接方式 | 验证方式 |
	// +------------------------------+
	// VER是SOCKS版本，这里应该是0x05；
	// NMETHODS是METHODS部分的长度；
	// METHODS是客户端支持的认证方式列表，每个方法占1字节。当前的定义是：
	// 0x00 不需要认证
	// 0x01 GSSAPI
	// 0x02 用户名、密码认证
	// 0x03 - 0x7F由IANA分配（保留）
	// 0x80 - 0xFE为私人方法保留
	// 0xFF 无可接受的方法

	sendData := []byte{0x05, 0x01, 0x00}
	_, err := socks5client.conn.Write(sendData)
	var getData [3]byte
	_, err = socks5client.conn.Read(getData[:])
	if err != nil {
		log.Println(err)
		return err
	}
	if getData[0] != 0x05 || getData[1] == 0xFF {
		return errErr{"socks5 first handshake failed!"}
	}
	// log.Println(sendData, "<-->", getData)
	log.Println("socks5 first handshake successful!")
	return nil
}

func (socks5client *socks5client) socks5SecondVerify(address string) error {
	// https://tools.ietf.org/html/rfc1928
	// 	Once the method-dependent subnegotiation has completed, the client
	// 	sends the request details.  If the negotiated method includes
	// 	encapsulation for purposes of integrity checking and/or
	// 	confidentiality, these requests MUST be encapsulated in the method-
	// 	dependent encapsulation.

	// 	The SOCKS request is formed as follows:

	// 		 +----+-----+-------+------+----------+----------+
	// 		 |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// 		 +----+-----+-------+------+----------+----------+
	// 		 | 1  |  1  | X'00' |  1   | Variable |    2     |
	// 		 +----+-----+-------+------+----------+----------+

	// 	  Where:

	// 		   o  VER    protocol version: X'05'
	// 		   o  CMD
	// 			  o  CONNECT X'01'
	// 			  o  BIND X'02'
	// 			  o  UDP ASSOCIATE X'03'
	// 		   o  RSV    RESERVED
	// 		   o  ATYP   address type of following address
	// 			  o  IP V4 address: X'01'
	// 			  o  DOMAINNAME: X'03'
	// 			  o  IP V6 address: X'04'
	// 		   o  DST.ADDR       desired destination address
	// 		   o  DST.PORT desired destination port in network octet
	// 			  order

	// 	The SOCKS server will typically evaluate the request based on source
	// 	and destination addresses, and return one or more reply messages, as
	// 	appropriate for the request type.

	//  5.  Addressing

	// 	In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
	// 	the type of address contained within the field:

	// 		   o  X'01'

	// 	the address is a version-4 IP address, with a length of 4 octets

	// 		   o  X'03'

	// 	the address field contains a fully-qualified domain name.  The first
	// 	octet of the address field contains the number of octets of name that
	// 	follow, there is no terminating NUL octet.

	// 		   o  X'04'

	// 	the address is a version-6 IP address, with a length of 16 octets.

	// 6.  Replies
	// The SOCKS request information is sent by the client as soon as it has
	// established a connection to the SOCKS server, and completed the
	// authentication negotiations.  The server evaluates the request, and
	// returns a reply formed as follows:

	// 	 +----+-----+-------+------+----------+----------+
	// 	 |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// 	 +----+-----+-------+------+----------+----------+
	// 	 | 1  |  1  | X'00' |  1   | Variable |    2     |
	// 	 +----+-----+-------+------+----------+----------+

	//   Where:

	// 	   o  VER    protocol version: X'05'
	// 	   o  REP    Reply field:
	// 		  o  X'00' succeeded
	// 		  o  X'01' general SOCKS server failure
	// 		  o  X'02' connection not allowed by ruleset
	// 		  o  X'03' Network unreachable
	// 		  o  X'04' Host unreachable
	// 		  o  X'05' Connection refused
	// 		  o  X'06' TTL expired
	// 		  o  X'07' Command not supported
	// 		  o  X'08' Address type not supported
	// 		  o  X'09' to X'FF' unassigned
	// 	   o  RSV    RESERVED
	// 	   o  ATYP   address type of following address
	// 		  o  IP V4 address: X'01'
	// 		  o  DOMAINNAME: X'03'
	// 		  o  IP V6 address: X'04'
	// 	   o  BND.ADDR       server bound address
	// 	   o  BND.PORT       server bound port in network octet order

	// Fields marked RESERVED (RSV) must be set to X'00'.

	// If the chosen method includes encapsulation for purposes of
	// authentication, integrity and/or confidentiality, the replies are
	// encapsulated in the method-dependent encapsulation.

	// CONNECT

	// In the reply to a CONNECT, BND.PORT contains the port number that the
	// server assigned to connect to the target host, while BND.ADDR
	// contains the associated IP address.  The supplied BND.ADDR is often
	// different from the IP address that the client uses to reach the SOCKS
	// server, since such servers are often multi-homed.  It is expected
	// that the SOCKS server will use DST.ADDR and DST.PORT, and the
	// client-side source address and port in evaluating the CONNECT
	// request.

	// BIND

	// The BIND request is used in protocols which require the client to
	// accept connections from the server.  FTP is a well-known example,
	// which uses the primary client-to-server connection for commands and
	// status reports, but may use a server-to-client connection for
	// transferring data on demand (e.g. LS, GET, PUT).

	// It is expected that the client side of an application protocol will
	// use the BIND request only to establish secondary connections after a
	// primary connection is established using CONNECT.  In is expected that
	// a SOCKS server will use DST.ADDR and DST.PORT in evaluating the BIND
	// request.

	// Two replies are sent from the SOCKS server to the client during a
	// BIND operation.  The first is sent after the server creates and binds
	// a new socket.  The BND.PORT field contains the port number that the
	// SOCKS server assigned to listen for an incoming connection.  The
	// BND.ADDR field contains the associated IP address.  The client will
	// typically use these pieces of information to notify (via the primary
	// or control connection) the application server of the rendezvous
	// address.  The second reply occurs only after the anticipated incoming
	// connection succeeds or fails.

	// In the second reply, the BND.PORT and BND.ADDR fields contain the
	// address and port number of the connecting host.

	// UDP ASSOCIATE

	// The UDP ASSOCIATE request is used to establish an association within
	// the UDP relay process to handle UDP datagrams.  The DST.ADDR and
	// DST.PORT fields contain the address and port that the client expects
	// to use to send UDP datagrams on for the association.  The server MAY
	// use this information to limit access to the association.  If the
	// client is not in possesion of the information at the time of the UDP
	// ASSOCIATE, the client MUST use a port number and address of all
	// zeros.

	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates.

	// In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
	// fields indicate the port number/address where the client MUST send
	// UDP request messages to be relayed.

	// Reply Processing

	// When a reply (REP value other than X'00') indicates a failure, the
	// SOCKS server MUST terminate the TCP connection shortly after sending
	// the reply.  This must be no more than 10 seconds after detecting the
	// condition that caused a failure.

	// If the reply code (REP value of X'00') indicates a success, and the
	// request was either a BIND or a CONNECT, the client may now start
	// passing data.  If the selected authentication method supports
	// encapsulation for the purposes of integrity, authentication and/or
	// confidentiality, the data are encapsulated using the method-dependent
	// encapsulation.  Similarly, when data arrives at the SOCKS server for
	// the client, the server MUST encapsulate the data as appropriate for
	// the authentication method in use.

	//
	//
	//
	// +-----------------------------------------------------------------------+
	// |					      socks5 protocol                              |
	// +-----------------------------------------------------------------------+
	// | socks_version | link_style | none | ipv4/ipv6/domain | address | port |
	// +-----------------------------------------------------------------------+
	// +-----------------------------------------------------------+
	// |					   socks5协议                           |
	// +-----------------------------------------------------------+
	// | socks版本 | 连接方式 | 保留字节 | 域名/ipv4/ipv6 | 域名 | 端口 |
	// +-----------------------------------------------------------+
	// 	VER是SOCKS版本，这里应该是0x05；
	// CMD是SOCK的命令码
	// 0x01表示CONNECT请求
	// 0x02表示BIND请求
	// 0x03表示UDP转发
	// RSV 0x00，保留
	// ATYP DST.ADDR类型
	// 0x01 IPv4地址，DST.ADDR部分4字节长度
	// 0x03 域名，DST.ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
	// 0x04 IPv6地址，16个字节长度。
	// DST.ADDR 目的地址
	// DST.PORT 网络字节序表示的目的端口

	// domain := "www.google.com"
	// before := []byte{5, 1, 0, 3, byte(len(server))}
	// de := []byte(domain)
	// port := []byte{0x01, 0xbb}
	// head_temp := append(before, de...)
	// sendData := append(head_temp, port...)

	serverAndPort := strings.Split(address, ":")
	serverB := []byte(serverAndPort[0])
	portI, err := strconv.Atoi(serverAndPort[1])
	if err != nil {
		log.Println(err)
		return err
	}
	var sendData []byte
	/*
		_, err = url.Parse(address)
		if err != nil {
			serverBB := strings.Split(serverAndPort[0], ".")
			serverBBA, err := strconv.Atoi(serverBB[0])
			if err != nil {
				fmt.Println(err)
				return err
			}
			serverBBB, err := strconv.Atoi(serverBB[1])
			if err != nil {
				fmt.Println(err)
				return err
			}
			serverBBC, err := strconv.Atoi(serverBB[2])
			if err != nil {
				fmt.Println(err)
				return err
			}
			serverBBD, err := strconv.Atoi(serverBB[3])
			if err != nil {
				fmt.Println(err)
				return err
			}
			sendData = []byte{0x5, 0x01, 0x00, 0x01, byte(serverBBA),
				byte(serverBBB), byte(serverBBC), byte(serverBBD),
				byte(portI >> 8), byte(portI & 255)}
		} else {
	*/
	// sendData := []byte{0x5, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x38}

	sendData = append(append([]byte{0x5, 0x01, 0x00, 0x03, byte(len(serverB))},
		serverB...), byte(portI>>8), byte(portI&255))
	// }]
	_, err = socks5client.conn.Write(sendData)
	if err != nil {
		log.Println(err)
		return err
	}

	var getData [1024]byte
	_, err = socks5client.conn.Read(getData[:])
	if err != nil {
		log.Println(err)
		return err
	}
	if getData[0] != 0x05 && getData[1] != 0x00 {
		return errErr{"socks5 second handshake failed!"}
	}
	// log.Println(sendData, "<-->", getData[0], getData[1])
	log.Println("socks5 second handshake successful!")
	return nil
}

//
//-----------------------------------------------------------------------------
//
func Http(server, port, socks5Server, socks5Port string) error {
	// var test delay
	// err = test.socks5_second_verify(socks5)
	// if err != nil {
	// 	log.Println(err)
	// }

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	l, err := net.Listen("tcp", server+":"+port)
	if err != nil {
		return err
	}
	for {
		client, err := l.Accept()
		if err != nil {
			return err
		}
		go httpHandleClientRequest(client, socks5Server, socks5Port)
	}
}

func httpHandleClientRequest(client net.Conn, socks5Server, socks5Port string) {
	if client == nil {
		return
	}
	defer client.Close()

	var b [3072]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println("请求长度:", n, err)
		return
	}
	log.Println("请求长度:", n)
	// log.Println(string(b[:]))
	// log.Println([]byte("Proxy-Connection"))
	var method, host, address string
	// log.Println(b)
	var indexByte int
	if bytes.Contains(b[:], []byte("\n")) {
		indexByte = bytes.IndexByte(b[:], '\n')
	} else {
		log.Println("请求不完整")
		return
	}
	// if indexByte >= 3072 && indexByte < 0 {
	// 	log.Println("越界错误")
	// 	return
	// }
	log.Println(string(b[:indexByte]))
	_, err = fmt.Sscanf(string(b[:indexByte]), "%s%s", &method, &host)
	if err != nil {
		log.Println(err)
		return
	}

	var hostPortURL *url.URL
	if strings.Contains(host, "http://") || strings.Contains(host, "https://") {
		if hostPortURL, err = url.Parse(host); err != nil {
			log.Println(err)
			log.Println(string(b[:]))
			return
		}
	} else {
		hostPortURL, err = url.Parse("//" + host)
		if err != nil {
			log.Println(err)
			log.Println(string(b[:]))
			return
		}
	}

	if hostPortURL.Opaque == "443" { //https访问
		address = hostPortURL.Scheme + ":443"
	} else { //http访问
		if strings.Index(hostPortURL.Host, ":") == -1 { //host不带端口， 默认80
			address = hostPortURL.Host + ":80"
		} else {
			address = hostPortURL.Host
		}
	}

	// log.Println(address, method)
	var socks5client socks5client
	socks5, err := socks5client.creatDial(socks5Server, socks5Port)
	for err != nil {
		log.Println("socks5 creat dial failed,10 seconds after retry.")
		log.Println(err)
		return
		// time.Sleep(10 * time.Second) // 10秒休む
		// socks5, err = socks5client.creatDial(socks5Server, socks5Port)
	}
	defer socks5.Close()

	if err = socks5client.socks5FirstVerify(); err != nil {
		log.Println(err)
		return
	}

	if err = socks5client.socks5SecondVerify(address); err != nil {
		log.Println(err)
		return
	}
	// server, err := net.Dial("tcp", address)
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	if method == "CONNECT" {
		// fmt.Fprintf(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	} else if method == "GET" {
		log.Println(address, hostPortURL.Host)
		newBefore := bytes.ReplaceAll(b[:n], []byte("http://"+address), []byte(""))
		newBefore = bytes.ReplaceAll(newBefore[:], []byte("http://"+hostPortURL.Host), []byte(""))
		var new []byte
		if bytes.Contains(newBefore[:], []byte("Proxy-Connection:")) {
			new = bytes.ReplaceAll(newBefore[:], []byte("Proxy-Connection:"), []byte("Connection:"))
		} else {
			new = newBefore
		}
		// 	// change2 := strings.ReplaceAll(change1, "GET http://222.195.242.240:8080/ HTTP/1.1", "GET / HTTP/1.1")
		// log.Println(string(new[:]))
		socks5.Write(new[:])
	} else if method == "POST" {
		// re, _ := regexp.Compile("POST http://.*/ HTTP/1.1")
		// c := re.ReplaceAll(b[:], []byte("POST / HTTP/1.1"))
		// c := strings.ReplaceAll(string(b[:]), "http://"+address, "")

		newBefore := bytes.ReplaceAll(b[:n], []byte("http://"+address), []byte(""))
		var new []byte
		if bytes.Contains(newBefore[:], []byte("Proxy-Connection:")) {
			new = bytes.ReplaceAll(newBefore[:], []byte("Proxy-Connection:"), []byte("Connection:"))
		} else {
			new = newBefore
		}
		// } else {
		// 	new = b[:]
		// }
		log.Println(string(new), len(new))
		socks5.Write(new[:len(new)/2])
		socks5.Write(new[len(new)/2:])
	} else {
		var new []byte
		if bytes.Contains(b[:n], []byte("Proxy-Connection:")) {
			new = bytes.ReplaceAll(b[:n], []byte("Proxy-Connection:"), []byte("Connection:"))
		} else {
			new = b[:n]
		}
		log.Println("未使用connect隧道,转发!")
		log.Println(string(new))
		socks5.Write(new)
	}

	go io.Copy(socks5, client)
	io.Copy(client, socks5)

	// var b [1024]byte
	// _, err := client.Read(b[:])
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
}

// func main() {
// var test delay
// conn := test.creat_dial("127.0.0.1", "1080")
// err := test.socks5_first_verify(conn)
// if err != nil {
// 	log.Println(err)
// }
// err = test.socks5_second_verify(conn)
// if err != nil {
// 	log.Println(err)
// }
// err = test.socks5_send_and_read(conn)
// if err != nil {
// 	log.Println(err)
// }
// conn.Close()

// if err := Http("", "8081", "", "1080"); err != nil {
// 	log.Println(err)
// }

// test := 443
// fmt.Println(test >> 8)
// fmt.Println(test & 255)

// server := "google.com:443"

/* 判断是域名还是ip
s, err := url.Parse(server)
if err != nil {
	log.Println(err)
}
log.Println(s)
*/
// port := "443"
// serverB := []byte(server)
// portI, err := strconv.Atoi(port)
// if err != nil {
// 	fmt.Println(err)
// }
// sendData := []byte{0x5, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x38}
// sendData := []byte{0x5, 0x01, 0x00, 0x03, byte(len(server))}
// sendData = append(sendData, serverB...)
// sendData = append(sendData, byte(portI>>8), byte(portI&255))
// log.Println(sendData)
// }

//
//
//
//
//
//
//
//
//
//
//
//
/*
func socks5_send_and_read(conn net.Conn) error {
	//进行数据请求
	re := "GET / HTTP/2.0\r\nHost: www.google.com\r\nConnection: close\r\nUser-agent: Mozilla/5.0\r\nAccept-Language: cn"
	_, err := conn.Write([]byte(re))
	if err != nil {
		fmt.Println(err)
		return err
	}
	var d [1024]byte

	temp := time.Now()
	_, err = conn.Read(d[:])
	if err != nil {
		fmt.Println(err)
		return err
	}
	delay := time.Since(temp)
	fmt.Println(delay)
	fmt.Println(string(d[:]))
	return nil
}
*/
// func Get_delay(local_server, local_port string) {
// 	var delay delay
// 	conn := delay.creat_dial(local_server, local_port)
// 	err := delay.socks5_first_verify(conn)
// 	if err != nil {
// 		log.Println("socks5 first verify error")
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}
// 	// err = delay.socks5_second_verify(conn)
// 	if err != nil {
// 		log.Println("socks5 second verify error")
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}
// 	err = delay.socks5_send_and_read(conn)
// 	if err != nil {
// 		log.Println("get delay last error")
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}
// 	conn.Close()
// }
