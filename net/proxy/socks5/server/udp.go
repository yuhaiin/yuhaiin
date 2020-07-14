package socks5server

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
)

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20

func Socks5UDPHandle() func(*net.UDPConn, net.Addr, []byte, func(string) (*net.UDPConn, error)) {
	return func(conn *net.UDPConn, addr net.Addr, bytes []byte, f func(string) (*net.UDPConn, error)) {
		err := udpHandle(conn, addr, bytes, f)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func udpHandle(listener *net.UDPConn, remoteAddr net.Addr, b []byte, f func(string) (*net.UDPConn, error)) error {
	if len(b) <= 0 {
		return fmt.Errorf("normalHandleUDP() -> b byte array is empty")
	}
	host, port, addrSize, err := ResolveAddr(b[3:])
	if err != nil {
		return err
	}
	if net.ParseIP(host) == nil {
		addr, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			return fmt.Errorf("resolve IP Addr -> %v", err)
		}
		host = addr.IP.String()
	}
	data := b[3+addrSize:]

	fmt.Println("Try to Get Target")
	target, err := f(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("get Target from f -> %v", err)
	}
	defer target.Close()
	fmt.Println("Get Target Successful")
	targetUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	_ = target.SetWriteDeadline(time.Now().Add(time.Second * 10))
	// write data to target and read the response back
	fmt.Println("UDP write", target.LocalAddr(), "->", targetUDPAddr)
	if _, err := target.WriteToUDP(data, targetUDPAddr); err != nil {
		return fmt.Errorf("write b to Target -> %v", err)
	}

	respBuff := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(respBuff[:])

	copy(respBuff[0:3], []byte{0, 0, 0})
	copy(respBuff[3:3+addrSize], data)
	_ = target.SetReadDeadline(time.Now().Add(time.Second * 10))
	n, addr, err := target.ReadFromUDP(respBuff[3+addrSize:])
	if err != nil {
		return fmt.Errorf("read From Target -> %v", err)
	}
	fmt.Println("UDP read from", addr.String())

	_, err = listener.WriteTo(respBuff[:n], remoteAddr)
	if err != nil {
		return fmt.Errorf("write to Listener -> %v", err)
	}
	return nil
}
