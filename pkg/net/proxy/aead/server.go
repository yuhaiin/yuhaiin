package aead

import (
	"context"
	"crypto/sha256"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterTransport(NewServer)
}

type Server struct {
	netapi.Listener
	crypto *encryptedHandshaker
	hash   []byte
}

func NewServer(cfg *listener.Aead, ii netapi.Listener) (netapi.Listener, error) {
	hash := Salt([]byte(cfg.GetPassword()))
	crypto := NewHandshaker(true, hash, []byte(cfg.GetPassword()))
	return &Server{crypto: crypto, Listener: ii, hash: hash}, nil
}

func (s *Server) Packet(ctx context.Context) (net.PacketConn, error) {
	lis, err := s.Listener.Packet(ctx)
	if err != nil {
		return nil, err
	}

	auth, err := GetAuth(s.hash)
	if err != nil {
		return nil, err
	}

	return NewAuthPacketConn(lis, auth.AEAD), nil
}

func Salt(password []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	return h.Sum(nil)
}

func (l *Server) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return l.crypto.Handshake(conn)
}
