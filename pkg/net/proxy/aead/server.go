package aead

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterTransport(NewServer)
}

type Server struct {
	netapi.Listener
	crypto       *encryptedHandshaker
	cryptoMethod protocol.AeadCryptoMethod
}

func NewServer(cfg *listener.Aead, ii netapi.Listener) (netapi.Listener, error) {
	crypto := NewHandshaker(true, []byte(cfg.GetPassword()), cfg.GetCryptoMethod())
	return &Server{
		crypto:       crypto,
		Listener:     ii,
		cryptoMethod: cfg.GetCryptoMethod(),
	}, nil
}

func (s *Server) Packet(ctx context.Context) (net.PacketConn, error) {
	lis, err := s.Listener.Packet(ctx)
	if err != nil {
		return nil, err
	}

	aead, err := newAead(s.crypto.aead, s.crypto.passwordHash)
	if err != nil {
		return nil, err
	}

	return NewAuthPacketConn(lis, aead), nil
}

func (l *Server) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return l.crypto.Handshake(conn)
}
