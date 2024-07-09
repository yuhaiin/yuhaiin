package tls

import (
	utls "github.com/refraction-networking/utls"
)

// Sniff returns the SNI server name inside the TLS ClientHello,
// without consuming any bytes from br.
// On any error, the empty string is returned.
//
// https://github.com/inetaf/tcpproxy/blob/3ce58045626c8bc343a593c90354975e61b1817a/sni.go#L83
func Sniff(buf []byte) (sni string) {
	const recordHeaderLen = 5

	if len(buf) < recordHeaderLen {
		return ""
	}

	const recordTypeHandshake = 0x16
	if buf[0] != recordTypeHandshake {
		return "" // Not TLS.
	}

	recLen := int(buf[3])<<8 | int(buf[4]) // ignoring version in hdr[1:3]

	if len(buf) < recordHeaderLen+recLen {
		return ""
	}

	clientHello := utls.UnmarshalClientHello(buf[recordHeaderLen : recordHeaderLen+recLen])

	if clientHello != nil {
		return clientHello.ServerName
	}

	return ""
}
