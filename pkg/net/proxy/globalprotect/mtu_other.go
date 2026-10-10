//go:build !unix

package globalprotect

import "net"

func tcpMSS(net.Conn) int { return 0 }
