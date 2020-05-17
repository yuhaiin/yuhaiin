package common

import (
	"net"
	"time"
)

var (
	ForwardTarget func(host string) (net.Conn, error)
)

func init() {
	ForwardTarget = func(host string) (net.Conn, error) {
		return net.DialTimeout("tcp", host, 5*time.Second)
	}
}
