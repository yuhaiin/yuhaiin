package aead

import (
	"context"
	"crypto/cipher"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Server struct {
	netapi.Listener
	cryptos []*encryptedHandshaker
}

func NewServer(cfg Config, ii netapi.Listener) (netapi.Listener, error) {
	passwords := cfg.Passwords
	if cfg.Auth != nil {
		passwords = cfg.Auth.InboundPasswords()
	} else if len(passwords) == 0 {
		passwords = []string{cfg.Password}
	}
	cryptos := make([]*encryptedHandshaker, 0, len(passwords))
	for _, password := range passwords {
		cryptos = append(cryptos, NewHandshaker(true, []byte(password), cfg.CryptoMethod))
	}

	return &Server{
		cryptos:  cryptos,
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

	var ciphers []cipher.AEAD
	for _, crypto := range s.cryptos {
		aead, err := newAead(crypto.aead, crypto.passwordHash)
		if err != nil {
			return nil, err
		}
		ciphers = append(ciphers, aead)
	}
	return NewMultiAuthPacketConn(lis, ciphers), nil
}

func (s *Server) Handshake(c net.Conn) net.Conn {
	return &serverConn{
		Conn:              c,
		cryptos:           s.cryptos,
		handshakeComplete: atomic.Bool{},
	}
}

type serverConn struct {
	net.Conn

	cryptos           []*encryptedHandshaker
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

	var conn net.Conn
	var err error
	if len(s.cryptos) == 1 {
		conn, err = s.cryptos[0].Handshake(s.Conn)
	} else {
		conn, err = handshakeServerMulti(s.Conn, s.cryptos)
	}
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
