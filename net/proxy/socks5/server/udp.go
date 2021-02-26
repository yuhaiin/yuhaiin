package socks5server

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/net/utils"
)

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20

func Socks5UDPHandle() func(net.PacketConn, net.Addr, []byte, func(string) (net.PacketConn, error)) {
	return func(listener net.PacketConn, addr net.Addr, bytes []byte, f func(string) (net.PacketConn, error)) {
		err := udpHandle(listener, addr, bytes, f)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func udpHandle(listener net.PacketConn, clientAddr net.Addr, b []byte, f func(string) (net.PacketConn, error)) error {
	if len(b) <= 0 {
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

	targetPacketConn, err := f(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("get Target from f -> %v", err)
	}
	defer targetPacketConn.Close()

	targetUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	_ = targetPacketConn.SetWriteDeadline(time.Now().Add(time.Second * 10))
	// write data to target and read the response back
	fmt.Println("UDP write", targetPacketConn.LocalAddr(), "->", targetUDPAddr)
	if _, err := targetPacketConn.WriteTo(data, targetUDPAddr); err != nil {
		return fmt.Errorf("write b to Target -> %v", err)
	}

	respBuff := utils.BuffPool.Get().([]byte)
	defer utils.BuffPool.Put(respBuff[:])

	copy(respBuff[0:3], []byte{0, 0, 0})
	copy(respBuff[3:3+addrSize], data)
	_ = targetPacketConn.SetReadDeadline(time.Now().Add(time.Second * 10))
	n, addr, err := targetPacketConn.ReadFrom(respBuff[3+addrSize:])
	if err != nil {
		return fmt.Errorf("read From Target -> %v", err)
	}
	fmt.Println("UDP read from", addr.String())

	_, err = listener.WriteTo(respBuff[:n], clientAddr)
	// _, err = targetPacketConn.WriteTo(respBuff[:n], clientAddr)
	if err != nil {
		return fmt.Errorf("write to Listener -> %v", err)
	}
	return nil
}
