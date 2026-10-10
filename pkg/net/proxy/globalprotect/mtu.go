package globalprotect

import (
	"crypto/tls"
	"net"
)

const (
	baseMTU       = 1406
	tlsGPSTHeader = 21 // five TLS bytes plus the sixteen-byte GlobalProtect header
)

func calculateMTU(conn *tls.Conn, configured int) int {
	if configured > 0 {
		return configured
	}

	if mss := tcpMSS(conn.NetConn()); mss > tlsGPSTHeader {
		return mss - tlsGPSTHeader
	}

	ipHeader := 20
	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		if addr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok && addr.IP.To4() == nil {
			ipHeader = 40
		}
	}

	// Match OpenConnect's fallback: use its conservative 1406-byte outer MTU
	// and account for the IP, TCP, TLS, and GlobalProtect frame headers.
	return baseMTU - ipHeader - 20 - tlsGPSTHeader
}
