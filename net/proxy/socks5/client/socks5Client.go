package socks5client

import (
	"errors"
	"net"
	"net/url"
	"strconv"
)

// Socks5Client socks5 client
// Conn will auto create
// if you socks5 need username and password please init it
// Server and Port is socks5 server's ip/domain and port
// Address need port,for example:www.google.com:443,1.1.1.1:443,[::1]:8080 <-- ipv6 need []
// KeepAliveTimeout 0: disable timeout , other: enable
type Socks5Client struct {
	Conn     net.Conn
	Username string
	Password string
	Server   string
	Port     string
	Address  string
}

func (socks5client *Socks5Client) creatDial() (net.Conn, error) {
	var err error
	socks5client.Conn, err = net.Dial("tcp", socks5client.Server+":"+socks5client.Port)
	if err != nil {
		return socks5client.Conn, err
	}
	return socks5client.Conn, nil
}

func (socks5client *Socks5Client) socks5FirstVerify() error {
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
	_, err := socks5client.Conn.Write(sendData)
	if err != nil {
		return err
	}
	getData := make([]byte, 3)
	_, err = socks5client.Conn.Read(getData[:])
	if err != nil {
		return err
	}
	if getData[0] != 0x05 || getData[1] == 0xFF {
		return errors.New("socks5 first handshake failed")
	}
	// 	SOCKS5 用户名密码认证方式
	// 在客户端、服务端协商使用用户名密码认证后，客户端发出用户名密码，格式为（以字节为单位）：
	// +------------+-----------+------+---------+-----+
	// | 鉴定协议版本 | 用户名长度	| 用户名 | 密码长度	| 密码 |
	// +------------+-----------+------+---------+------+
	// |      1	 |    1      |  动态 |    1    | 动态 |
	// +------------+-----------+------+---------+------+
	// 鉴定协议版本当前为 0x01.

	// 服务器鉴定后发出如下回应：
	// +----------+-------+
	// |鉴定协议版本|鉴定状态|
	// +----------+-------+
	// |    1     |   1   |
	// +----------+-------+
	// 其中鉴定状态 0x00 表示成功，0x01 表示失败。
	if getData[1] == 0x02 {
		sendData := append(
			append(
				append(
					[]byte{0x01, byte(len(socks5client.Username))},
					[]byte(socks5client.Username)...),
				byte(len(socks5client.Password))),
			[]byte(socks5client.Password)...)
		_, _ = socks5client.Conn.Write(sendData)
		getData := make([]byte, 3)
		_, err = socks5client.Conn.Read(getData[:])
		if err != nil {
			return err
		}
		if getData[1] == 0x01 {
			return errors.New("username or password not correct,socks5 handshake failed")
		}
	}
	// log.Println(sendData, "<-->", getData)
	// log.Println("socks5 first handshake successful!")
	return nil
}

func (socks5client *Socks5Client) socks5SecondVerify() error {
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
	// client is not in possession of the information at the time of the UDP
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
	// 	0x01表示CONNECT请求
	// 	0x02表示BIND请求
	// 	0x03表示UDP转发
	// RSV 0x00，保留
	// ATYP DST.ADDR类型
	// 0x01 IPv4地址，DST.ADDR部分4字节长度
	// 0x03 域名，DST.ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾。
	// 0x04 IPv6地址，16个字节长度。
	// DST.ADDR 目的地址
	// DST.PORT 网络字节序表示的目的端口
	address, err := url.Parse("//" + socks5client.Address)
	if err != nil {
		return err
	}
	serverPort, err := strconv.Atoi(address.Port())
	if err != nil {
		return err
	}
	var sendData []byte
	if serverIP := net.ParseIP(address.Hostname()); serverIP != nil {
		if serverIPv4 := serverIP.To4(); serverIPv4 != nil {
			sendData = []byte{0x5, 0x01, 0x00, 0x01, serverIPv4[0],
				serverIPv4[1], serverIPv4[2], serverIPv4[3],
				byte(serverPort >> 8), byte(serverPort & 255)}
		} else {
			sendData = append(
				append(
					[]byte{0x5, 0x01, 0x00, 0x04}, serverIP.To16()...),
				byte(serverPort>>8), byte(serverPort&255))
		}
		// sendData := []byte{0x5, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x38}
	} else {
		sendData = append(
			append(
				[]byte{0x5, 0x01, 0x00, 0x03, byte(len(address.Hostname()))},
				[]byte(address.Hostname())...), byte(serverPort>>8),
			byte(serverPort&255))
	}

	if _, err = socks5client.Conn.Write(sendData); err != nil {
		return err
	}

	getData := make([]byte, 1024)
	if _, err = socks5client.Conn.Read(getData[:]); err != nil {
		return err
	}
	if getData[0] != 0x05 || getData[1] != 0x00 {
		return errors.New("socks5 second handshake failed")
	}
	// log.Println(sendData, "<-->", getData[0], getData[1])
	// log.Println("socks5 second handshake successful!")
	return nil
}

// NewSocks5Client <--
func (socks5client *Socks5Client) NewSocks5Client() (net.Conn, error) {
	// var socks5client socks5client
	var err error
	socks5client.Conn, err = socks5client.creatDial()
	for err != nil {
		return socks5client.Conn, err
		// time.Sleep(10 * time.Second) // 10秒休む
	}

	if err = socks5client.socks5FirstVerify(); err != nil {
		return socks5client.Conn, err
	}

	if err = socks5client.socks5SecondVerify(); err != nil {
		return socks5client.Conn, err
	}
	return socks5client.Conn, nil
}

// NewSocks5ClientOnlyFirstVerify <--
func (socks5client *Socks5Client) NewSocks5ClientOnlyFirstVerify() (net.Conn, error) {
	// var socks5client socks5client
	var err error
	socks5client.Conn, err = socks5client.creatDial()
	for err != nil {
		return socks5client.Conn, err
		// time.Sleep(10 * time.Second) // 10秒休む
	}

	if err = socks5client.socks5FirstVerify(); err != nil {
		return socks5client.Conn, err
	}

	return socks5client.Conn, nil
}
