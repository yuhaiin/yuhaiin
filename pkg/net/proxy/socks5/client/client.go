package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

// https://tools.ietf.org/html/rfc1928
// client socks5 client
type client struct {
	username string
	password string

	hostname string
	dialer   proxy.Proxy
}

// NewSocks5 returns a new Socks5 client
func NewSocks5(config *node.Protocol_Socks5) node.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		return &client{
			dialer:   dialer,
			username: config.Socks5.User,
			password: config.Socks5.Password,
			hostname: config.Socks5.Hostname,
		}, nil
	}
}

func (s *client) Conn(host proxy.Address) (net.Conn, error) {
	conn, err := s.dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}

	err = s.handshake1(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("first hand failed: %v", err)
	}

	_, err = s.handshake2(conn, Connect, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("second hand failed: %v", err)
	}

	return conn, nil
}

func (s *client) handshake1(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return fmt.Errorf("write sock5 header failed: %w", err)
	}

	header := make([]byte, 2)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		return fmt.Errorf("read header failed: %w", err)
	}

	if header[0] != 0x05 || header[1] == 0xFF {
		return errors.New("unknown socks5 version")
	}

	//username and password
	if header[1] == 0x02 {
		req := utils.GetBuffer()
		defer utils.PutBuffer(req)

		req.Write([]byte{0x01, byte(len(s.username))})
		req.WriteString(s.username)
		req.WriteByte(byte(len(s.password)))
		req.WriteString(s.password)

		_, err = conn.Write(req.Bytes())
		if err != nil {
			return fmt.Errorf("write auth data failed: %w", err)
		}

		_, err = io.ReadFull(conn, header)
		if err != nil {
			return fmt.Errorf("read auth data failed: %w", err)
		}
		if header[1] == 0x01 {
			return errors.New("username or password not correct,socks5 handshake failed")
		}
	}
	return nil
}

type CMD byte

const (
	Connect CMD = 0x01
	Bind    CMD = 0x02
	Udp     CMD = 0x03

	IPv4   byte = 0x01
	Domain byte = 0x03
	IPv6   byte = 0x04
)

func (s *client) handshake2(conn net.Conn, cmd CMD, address proxy.Address) (target proxy.Address, err error) {
	req := utils.GetBuffer()
	defer utils.PutBuffer(req)

	req.Write([]byte{0x05, byte(cmd), 0x00})
	req.Write(ParseAddr(address))

	if _, err = conn.Write(req.Bytes()); err != nil {
		return nil, err
	}

	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != 0x05 || header[1] != 0x00 {
		return nil, errors.New("socks5 second handshake failed")
	}

	addr, _, err := ResolveAddr("tcp", conn)
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed: %w", err)
	}

	if addr.Type() == proxy.IP && yerror.Must(addr.IP()).IsUnspecified() {
		addr = proxy.ParseAddressSplit("", s.hostname, addr.Port())
	}

	return addr, nil
}

func (s *client) PacketConn(host proxy.Address) (net.PacketConn, error) {
	conn, err := s.dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial tcp failed: %v", err)
	}

	err = s.handshake1(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("first hand failed: %v", err)
	}

	addr, err := s.handshake2(conn, Udp, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("second hand failed: %v", err)
	}

	pc, err := s.dialer.PacketConn(addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("listen udp failed: %v", err)
	}

	pc = newSocks5PacketConn(pc, conn, addr)

	go func() {
		io.Copy(io.Discard, conn)
		pc.Close()
	}()

	return pc, nil
}

type socks5PacketConn struct {
	net.PacketConn
	tcp    net.Conn
	server proxy.Address
}

func newSocks5PacketConn(local net.PacketConn, tcp net.Conn, target proxy.Address) net.PacketConn {
	return &socks5PacketConn{local, tcp, target}
}

func (s *socks5PacketConn) Close() error {
	s.tcp.Close()
	return s.PacketConn.Close()
}

func (s *socks5PacketConn) WriteTo(p []byte, addr net.Addr) (_ int, err error) {
	ad, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("parse addr failed: %v", err)
	}
	return s.PacketConn.WriteTo(bytes.Join([][]byte{{0, 0, 0}, ParseAddr(ad), p}, []byte{}), s.server)
}

func (s *socks5PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, addr, fmt.Errorf("read from remote failed: %v", err)
	}

	adr, size, err := ResolveAddr("udp", bytes.NewReader(p[3:n]))
	if err != nil {
		return 0, addr, fmt.Errorf("resolve addr failed: %v", err)
	}

	prefix := 3 + size

	if n < prefix {
		return 0, addr, fmt.Errorf("slice out of range, get: %d less %d", n, prefix)
	}

	copy(p[0:], p[prefix:n])

	return n - prefix, adr, nil
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
