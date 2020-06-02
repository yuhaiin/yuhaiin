package socks5server

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
)

// https://github.com/haxii/socks5/blob/bb9bca477f9b3ca36fa3b43e3127e3128da1c15b/udp.go#L20
var (
	Proxy func(listener *net.UDPConn, remoteAddr net.Addr, b []byte) (err error)
)

func (s *Server) UpdateUDPListenAddr(host string) error {
	if s.udpListener != nil {
		_ = s.udpListener.Close()
	}
	localAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		log.Printf("UDP server address error: %s\n", err.Error())
		return err
	}
	s.udpListener, err = net.ListenUDP("udp", localAddr)
	return err
}

func (s *Server) UDP(host string) (err error) {
	if err = s.UpdateUDPListenAddr(host); err != nil {
		return err
	}
	go func() {
		s.handleUDP()
	}()
	return
}

func (s *Server) handleUDP() {
	b := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(b)
	for {
		n, remoteAddr, err := s.udpListener.ReadFromUDP(b)
		if err != nil {
			if s.closed {
				break
			}
			fmt.Printf("error during read: %s", err)
		}

		if Proxy == nil {
			goto normalUDP
		}
		if err = Proxy(s.udpListener, remoteAddr, b[:n]); err != nil {
			goto normalUDP
		}
		return

	normalUDP:
		normalHandleUDP(s.udpListener, remoteAddr, b[:n])
	}
}

func normalHandleUDP(listener *net.UDPConn, remoteAddr net.Addr, b []byte) (err error) {
	//RSV := b[:2]
	//FRAG := b[2:3]

	host, port, addrSize, err := ResolveAddr(b[3:])
	if net.ParseIP(host) == nil {
		addr, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			return err
		}
		host = addr.IP.String()
	}
	data := b[3+addrSize:]

	// make a writer and write to dst
	targetUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	target, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0}, targetUDPAddr)
	if err != nil {
		return err
	}
	defer target.Close()

	_ = target.SetReadDeadline(time.Now().Add(time.Second * 5))

	// write data to target and read the response back
	if _, err := target.Write(data); err != nil {
		return err
	}

	respBuff := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(respBuff[:cap(respBuff)])

	copy(respBuff[0:3], []byte{0, 0, 0})
	copy(respBuff[3:3+addrSize], data)
	n, err := target.Read(respBuff[3+addrSize:])
	if err != nil {
		return err
	}
	respBuff = respBuff[:3+addrSize+n]
	_, err = listener.WriteTo(respBuff, remoteAddr)
	return err
}
