//+build windows

package redirserver

import "net"

func RedirHandle() func(net.Conn, func(string) (net.Conn, error)) {
	return nil
}
