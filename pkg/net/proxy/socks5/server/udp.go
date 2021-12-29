package socks5server

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
// https://github.com/net-byte/socks5-server/blob/main/socks5/udp.go
type udpHandler struct {
	connMap sync.Map
}

func (u *udpHandler) handle(b []byte, rw func([]byte), f proxy.Proxy) error {
	if len(b) == 0 {
		return fmt.Errorf("normalHandleUDP() -> b byte array is empty")
	}
	/*
	* progress
	* 1. listener get client data
	* 2. get local/proxy packetConn
	* 3. write client data to local/proxy packetConn
	* 4. read data from local/proxy packetConn
	* 5. write data that from remote to client
	 */
	host, port, addrSize, err := ResolveAddr(b[3:])
	if err != nil {
		return fmt.Errorf("resolve socks5 address failed: %v", err)
	}

	if net.ParseIP(host) == nil {
		addr, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			return fmt.Errorf("resolve IP Addr failed: %v", err)
		}
		host = addr.IP.String()
	}

	h := net.JoinHostPort(host, strconv.Itoa(port))
	var conn net.PacketConn
	c, ok := u.connMap.Load(h)
	if ok {
		conn = c.(net.PacketConn)
	}

	if conn == nil {
		conn, err = f.PacketConn(h)
		if err != nil {
			return fmt.Errorf("get packetConn from f failed: %v", err)
		}
		conn = &udpHandlerPacketConn{key: h, m: &u.connMap, PacketConn: conn}
		u.connMap.Store(h, conn)
	}
	defer conn.Close()

	target, err := net.ResolveUDPAddr("udp", h)
	if err != nil {
		return fmt.Errorf("resolve udp addr failed: %v", err)
	}
	// write data to target and read the response back
	logasfmt.Println("UDP write", conn.LocalAddr(), "->", target)
	// fmt.Println("write data:", data, "origin:", b)

	conn.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = conn.WriteTo(b[3+addrSize:], target)
	if err != nil {
		return fmt.Errorf("write data to remote packetConn failed: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 60))
	buf := make([]byte, 1024)
	var n, all int
	var addr net.Addr
	for {
		n, addr, err = conn.ReadFrom(buf)
		if n == 0 || err != nil {
			logasfmt.Println("read data From remote packetConn failed:", err)
			break
		}
		all += n
		bf := bytes.NewBuffer(b[:3+addrSize]) // copy addr []byte{0,0,0,addr...}
		bf.Write(buf[:n])
		rw(bf.Bytes())
	}

	logasfmt.Printf("UDP read data(size:%d) from %s\n", all, addr.String())
	return nil
}

var _ net.PacketConn = (*udpHandlerPacketConn)(nil)

type udpHandlerPacketConn struct {
	net.PacketConn
	key string
	m   *sync.Map
}

func (u *udpHandlerPacketConn) Close() error {
	u.m.Delete(u.key)
	return u.PacketConn.Close()
}
