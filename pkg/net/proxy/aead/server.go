package aead

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterTransport(NewServer)
}

type Server struct {
	netapi.Listener
	crypto *encryptedHandshaker
}

func NewServer(cfg *config.Aead, ii netapi.Listener) (netapi.Listener, error) {
	crypto := NewHandshaker(true, []byte(cfg.GetPassword()), cfg.GetCryptoMethod())

	return &Server{
		crypto:   crypto,
		Listener: ii,
	}, nil
}

func (s *Server) Accept() (net.Conn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return s.Handshake(conn), nil
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

func (s *Server) Handshake(c net.Conn) net.Conn {
	return &serverConn{
		Conn:              c,
		crypto:            s.crypto,
		handshakeComplete: atomic.Bool{},
	}
}

type serverConn struct {
	net.Conn

	crypto            *encryptedHandshaker
	handshakeComplete atomic.Bool
	mu                sync.Mutex
}

func (s *serverConn) handshake() error {
	if s.handshakeComplete.Load() {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handshakeComplete.Load() {
		return nil
	}

	defer s.handshakeComplete.Store(true)

	conn, err := s.crypto.Handshake(s.Conn)
	if err != nil {
		return err
	}
	s.Conn = conn
	return nil
}

func (s *serverConn) Read(b []byte) (int, error) {
	if err := s.handshake(); err != nil {
		return 0, err
	}
	return s.Conn.Read(b)
}

func (s *serverConn) Write(b []byte) (int, error) {
	if err := s.handshake(); err != nil {
		return 0, err
	}
	return s.Conn.Write(b)
}
