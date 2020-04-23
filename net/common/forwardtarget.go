package common

import "net"

var (
	ForwardTarget func(host string) (net.Conn, error)
)
