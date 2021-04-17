//+build windows

package server

import "net"

func RedirHandle() func(net.Conn, proxy.Proxy) {
	return nil
}

func NewServer(host string) (proxy.Server, error) {
	return nil, fmt.Errorf("windows not support redir")
}
