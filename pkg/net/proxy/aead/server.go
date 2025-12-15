package aead

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterTransport(NewServer)
}

type Server struct {
	netapi.PacketListener
	crypto *encryptedHandshaker
	*netapi.HandshakeListener
}

func NewServer(cfg *config.Aead, ii netapi.Listener) (netapi.Listener, error) {
	crypto := NewHandshaker(true, []byte(cfg.GetPassword()), cfg.GetCryptoMethod())
	s := &Server{
		PacketListener: ii,
		crypto:         crypto,
	}

	s.HandshakeListener = netapi.NewHandshakeListener(ii,
		func(ctx context.Context, c net.Conn) (net.Conn, error) {
			return crypto.Handshake(c)
		},
		log.Error)

	return s, nil
}

func (s *Server) Packet(ctx context.Context) (net.PacketConn, error) {
	lis, err := s.PacketListener.Packet(ctx)
	if err != nil {
		return nil, err
	}

	aead, err := newAead(s.crypto.aead, s.crypto.passwordHash)
	if err != nil {
		return nil, err
	}

	return NewAuthPacketConn(lis, aead), nil
}

func (s *Server) Close() error {
	return s.HandshakeListener.Close()
}
