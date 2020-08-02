//+build !windows

package redirserver

import (
	"log"
	"net"
)

func RedirHandle() func(net.Conn, func(string) (net.Conn, error)) {
	return func(conn net.Conn, f func(string) (net.Conn, error)) {
		err := handle(conn, f)
		if err != nil {
			log.Println(err)
			return
		}
	}
}
