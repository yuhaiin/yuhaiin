package socks5client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
)

// https://tools.ietf.org/html/rfc1928
// client socks5 client
// host socks5 server's ip/domain and port
type client struct {
	hostname string
	port     string
	host     string
	username string
	password string

	proxy.Proxy
}

func NewSocks5Client(host, port, user, password string) proxy.Proxy {
	x := &client{
		username: user,
		hostname: host,
		port:     port,
		host:     net.JoinHostPort(host, port),
		password: password,
		Proxy:    simple.NewSimple(host, port),
	}
	return x
}

func (s *client) Conn(host string) (net.Conn, error) {
	conn, err := s.Proxy.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}

	err = s.handshake1(conn)
	if err != nil {
		return nil, fmt.Errorf("first hand failed: %v", err)
	}

	_, err = s.handshake2(conn, connect, host)
	if err != nil {
		return nil, fmt.Errorf("second hand failed: %v", err)
	}

	return conn, nil
}

func (s *client) handshake1(conn net.Conn) error {
	sendData := bytes.NewBuffer([]byte{0x05, 0x01, 0x00})
	_, err := conn.Write(sendData.Bytes())
	if err != nil {
		return fmt.Errorf("firstVerify:sendData -> %v", err)
	}
	getData := make([]byte, 3)
	_, err = conn.Read(getData[:])
	if err != nil {
		return fmt.Errorf("firstVerify:Read -> %v", err)
	}
	if getData[0] != 0x05 || getData[1] == 0xFF {
		return fmt.Errorf("firstVerify:checkVersion -> %v", errors.New("socks5 first handshake failed"))
	}

	//username and password
	if getData[1] == 0x02 {
		sendData.Write([]byte{0x01, byte(len(s.username))})
		sendData.WriteString(s.username)
		sendData.WriteByte(byte(len(s.password)))
		sendData.WriteString(s.password)
		_, _ = conn.Write(sendData.Bytes())

		_, err = conn.Read(getData[:])
		if err != nil {
			return fmt.Errorf("firstVerify:Read2 -> %v", err)
		}
		if getData[1] == 0x01 {
			return fmt.Errorf("firstVerify -> %v", errors.New("username or password not correct,socks5 handshake failed"))
		}
	}
	return nil
}

type cmd byte

const (
	connect cmd = 0x01
	bind    cmd = 0x02
	udp     cmd = 0x03

	ipv4       byte = 0x01
	domainName byte = 0x03
	ipv6       byte = 0x04
)

type header struct {
	VER  byte
	REP  byte
	RSV  byte
	ATYP byte
	ADDR string
	PORT int
}

func (s *client) handshake2(conn net.Conn, cmd cmd, address string) (header, error) {
	addr, err := ParseAddr(address)
	if err != nil {
		return header{}, fmt.Errorf("secondVerify:ParseAddr -> %v", err)
	}
	sendData := bytes.NewBuffer([]byte{0x05, byte(cmd), 0x00})
	sendData.Write(addr)

	if _, err = conn.Write(sendData.Bytes()); err != nil {
		return header{}, err
	}

	getData := make([]byte, 1024)
	n, err := conn.Read(getData[:])
	if err != nil {
		return header{}, err
	}
	if getData[0] != 0x05 || getData[1] != 0x00 {
		return header{}, errors.New("socks5 second handshake failed")
	}

	dst, port, _, err := ResolveAddr(getData[3:n])
	if err != nil {
		return header{}, err
	}

	return header{
		VER:  getData[0],
		REP:  getData[1],
		RSV:  getData[2],
		ATYP: getData[3],
		ADDR: dst,
		PORT: port,
	}, nil
}

func (s *client) PacketConn(host string) (net.PacketConn, error) {
	conn, err := s.Proxy.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial tcp failed: %v", err)
	}

	err = s.handshake1(conn)
	if err != nil {
		return nil, fmt.Errorf("first hand failed: %v", err)
	}

	r, err := s.handshake2(conn, udp, host)
	if err != nil {
		return nil, fmt.Errorf("second hand failed: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(r.ADDR, strconv.Itoa(r.PORT)))
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed: %v", err)
	}

	go func() {
		t := time.NewTicker(time.Second * 3)
		for range t.C {
			_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			if err != nil {
				log.Printf("write udp response failed: %v", err)
				break
			}
		}
	}()
	return newSocks5PacketConn(host, addr, conn)
}

type socks5PacketConn struct {
	net.PacketConn
	addr   []byte
	server net.Addr

	tcp net.Conn
}

func newSocks5PacketConn(address string, server net.Addr, tcp net.Conn) (net.PacketConn, error) {
	addr, err := ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %v", err)
	}

	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("create packet failed: %v", err)
	}

	return &socks5PacketConn{
		server:     server,
		addr:       addr,
		PacketConn: conn,
		tcp:        tcp,
	}, nil

}

func (s *socks5PacketConn) Close() error {
	s.tcp.Close()
	return s.PacketConn.Close()
}

func (s *socks5PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return s.PacketConn.WriteTo(bytes.Join([][]byte{{0, 0, 0}, s.addr, p}, []byte{}), s.server)
}

func (s *socks5PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	z := make([]byte, len(p))
	n, addr, err := s.PacketConn.ReadFrom(z)
	if err != nil {
		return 0, addr, fmt.Errorf("read from remote failed: %v", err)
	}

	prefix := 3 + len(s.addr)

	if n < prefix {
		return 0, addr, fmt.Errorf("slice out of range, get: %d less %d", n, 3+len(s.addr))
	}

	copy(p[0:], z[prefix:n])

	// log.Printf("z: %v,\n p: %v\n", z[:], p[:])
	return n - prefix, addr, nil
}

func ParseAddr(hostname string) (data []byte, err error) {
	hostname, port, err := net.SplitHostPort(hostname)
	if err != nil {
		return nil, err
	}
	serverPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	sendData := bytes.NewBuffer(nil)
	if serverIP := net.ParseIP(hostname); serverIP != nil {
		if serverIPv4 := serverIP.To4(); serverIPv4 != nil {
			sendData.WriteByte(0x01)
			sendData.Write(serverIP.To4())
		} else {
			sendData.WriteByte(0x04)
			sendData.Write(serverIP.To16())
		}
	} else {
		sendData.WriteByte(0x03)
		sendData.WriteByte(byte(len(hostname)))
		sendData.WriteString(hostname)
	}
	sendData.WriteByte(byte(serverPort >> 8))
	sendData.WriteByte(byte(serverPort & 255))
	return sendData.Bytes(), nil
}

func ResolveAddr(raw []byte) (dst string, port, size int, err error) {
	if len(raw) <= 0 {
		return "", 0, 0, fmt.Errorf("ResolveAddr() -> raw byte array is empty")
	}
	targetAddrRawSize := 1
	switch raw[0] {
	case ipv4:
		dst = net.IP(raw[targetAddrRawSize : targetAddrRawSize+4]).String()
		targetAddrRawSize += 4
	case ipv6:
		if len(raw) < 1+16+2 {
			return "", 0, 0, errors.New("errShortAddrRaw")
		}
		dst = net.IP(raw[1 : 1+16]).String()
		targetAddrRawSize += 16
	case domainName:
		addrLen := int(raw[1])
		if len(raw) < 1+1+addrLen+2 {
			// errShortAddrRaw
			return "", 0, 0, errors.New("error short address raw")
		}
		dst = string(raw[1+1 : 1+1+addrLen])
		targetAddrRawSize += 1 + addrLen
	default:
		// errUnrecognizedAddrType
		return "", 0, 0, errors.New("udp socks: Failed to get UDP package header")
	}
	port = (int(raw[targetAddrRawSize]) << 8) | int(raw[targetAddrRawSize+1])
	targetAddrRawSize += 2
	return dst, port, targetAddrRawSize, nil
}

func ResolveAddrReader(r io.Reader) (hostname string, port, size int, err error) {
	byteBuf := [1]byte{}
	_, err = io.ReadFull(r, byteBuf[:])
	if err != nil {
		err = fmt.Errorf("unable to read ATYP: %w", err)
		return
	}
	switch byteBuf[0] {
	case ipv4:
		var buf [6]byte
		_, err = io.ReadFull(r, buf[:])
		if err != nil {
			err = fmt.Errorf("failed to read IPv4: %w", err)
			return
		}
		hostname = net.IP(buf[0:4]).String()
		port = int(binary.BigEndian.Uint16(buf[4:6]))
	case ipv6:
		var buf [18]byte
		_, err = io.ReadFull(r, buf[:])
		if err != nil {
			err = fmt.Errorf("failed to read IPv6: %w", err)
			return
		}
		hostname = net.IP(buf[0:16]).String()
		port = int(binary.BigEndian.Uint16(buf[16:18]))
	case domainName:
		_, err = io.ReadFull(r, byteBuf[:])
		length := byteBuf[0]
		if err != nil {
			err = fmt.Errorf("failed to read domain name length")
			return
		}
		buf := make([]byte, length+2)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			err = fmt.Errorf("failed to read domain name")
			return
		}
		// the fucking browser uses IP as a domain name sometimes
		host := buf[0:length]
		hostname = string(host)
		port = int(binary.BigEndian.Uint16(buf[length : length+2]))
	default:
		err = fmt.Errorf("invalid ATYP " + strconv.FormatInt(int64(byteBuf[0]), 10))
		return
	}
	return
}

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

// second handshake

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
