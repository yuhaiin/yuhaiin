package netapi

import (
	"crypto/tls"
	"net"
)

// WithoutTLSMetadata prevents net/http from using an underlying transport's
// TLS state to select the application protocol. Handshakes and encrypted I/O
// still run through the original connection, with its TLS configuration intact.
func WithoutTLSMetadata(listener net.Listener) net.Listener {
	return tlsMetadataListener{listener}
}

type tlsMetadataListener struct {
	net.Listener
}

func (l tlsMetadataListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if _, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return struct{ net.Conn }{conn}, nil
	}
	return conn, nil
}
