package hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/obfs"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

// Packet IDs must be unique across listeners and reconnects, not just within a
// QUIC connection: the inbound NAT table keys sessions by MigrateID when set.
var packetIDs atomic.Uint64

type Server struct {
	netapi.EmptyInterface
	core      *nativeServer
	listener  netapi.Listener
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	redirect  io.Closer
}

func NewServer(config contract.Hysteria2Protocol, tlsConfig *tls.Config, lis netapi.Listener, handler netapi.Handler, verifiers ...proxyauth.Verifier) (*Server, error) {
	var verify proxyauth.Verifier
	if len(verifiers) > 0 {
		verify = verifiers[0]
	}
	validationAuth := config.Auth
	if verify != nil && validationAuth == "" {
		validationAuth = "user-credentials"
	}
	if err := validateOptions(validationAuth, config.SalamanderPassword, config.UploadBPS, config.DownloadBPS); err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, errors.New("hysteria2 TLS config is nil")
	}
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil && tlsConfig.GetConfigForClient == nil {
		return nil, errors.New("hysteria2 TLS config has no server certificate")
	}
	packet, err := lis.Packet(context.Background())
	if err != nil {
		return nil, err
	}
	if config.SalamanderPassword != "" {
		packet, err = obfs.WrapPacketConnSalamander(packet, []byte(config.SalamanderPassword))
		if err != nil {
			return nil, err
		}
	}
	var redirect io.Closer
	if config.HopPorts != "" {
		redirect, err = newHopRedirect(packet.LocalAddr(), config.HopPorts)
		if err != nil {
			return nil, err
		}
	}
	core, err := newNativeServer(packet, tlsConfig, handler, config.Auth, config.UploadBPS, config.DownloadBPS, config.IgnoreClientBandwidth, config.DisableUDP)
	if err != nil {
		if redirect != nil {
			err = errors.Join(err, redirect.Close())
		}
		return nil, err
	}
	core.authenticate = verify
	s := &Server{core: core, listener: lis, done: make(chan struct{}), redirect: redirect}
	go func() {
		defer close(s.done)
		if err := core.Serve(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debug("hysteria2 serve", "err", err)
		}
	}()
	return s, nil
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		if s.redirect != nil {
			s.closeErr = s.redirect.Close()
		}
		s.closeErr = errors.Join(s.closeErr, s.core.Close())
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = errors.Join(s.closeErr, err)
		}
		<-s.done
	})
	return s.closeErr
}

type serverPacketConn struct {
	source  net.Addr
	handler netapi.Handler
	id      uint64
	packets chan datagram
	done    chan struct{}
	mu      sync.Mutex
	closed  bool
	stop    func() bool

	// A UDP session usually talks to one peer, so the last address is reused
	// instead of parsing or formatting it again for every packet.
	// lastTarget* belong to the single WriteTo caller; lastReply* to mu.
	lastTarget     string
	lastTargetAddr netapi.Address
	lastReplyKey   uint64
	lastReply      string
}

func newServerPacketConn(ctx context.Context, source net.Addr, handler netapi.Handler) *serverPacketConn {
	p := &serverPacketConn{source: source, handler: handler, id: packetIDs.Add(1), packets: make(chan datagram, 128), done: make(chan struct{})}
	p.mu.Lock()
	p.stop = context.AfterFunc(ctx, func() { _ = p.Close() })
	p.mu.Unlock()
	return p
}

func (p *serverPacketConn) ReadFrom(b []byte) (int, string, error) {
	packet, err := p.readPacket()
	if err != nil {
		return 0, "", err
	}
	n := copy(b, packet.data)
	pool.PutBytes(packet.data)
	return n, packet.addr, nil
}

// readPacket hands the queued pooled reply to the caller, which must return
// packet.data with pool.PutBytes. This avoids a full-size read buffer for
// every UDP session that only exists to copy the payload once more.
func (p *serverPacketConn) readPacket() (datagram, error) {
	select {
	case <-p.done:
		return datagram{}, net.ErrClosed
	case packet := <-p.packets:
		return packet, nil
	}
}

func (p *serverPacketConn) WriteTo(b []byte, target string) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	addr := p.lastTargetAddr
	if addr == nil || target != p.lastTarget {
		var err error
		if addr, err = netapi.ParseAddress("udp", target); err != nil {
			return 0, err
		}
		p.lastTarget, p.lastTargetAddr = target, addr
	}
	p.handler.HandlePacket(netapi.NewPacket(p.source, addr, pool.Clone(b), netapi.WriteBackFunc(p.writeBack), netapi.WithMigrateID(p.id)))
	return len(b), nil
}

func (p *serverPacketConn) writeBack(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("hysteria2 UDP reply has no address")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	data := pool.Clone(b)
	select {
	case p.packets <- datagram{data, p.replyString(addr)}:
	default:
		pool.PutBytes(data)
	}
	return len(b), nil
}

// replyString formats addr, reusing the previous result for the same
// [netapi.Address]. The caller holds p.mu.
func (p *serverPacketConn) replyString(addr net.Addr) string {
	a, ok := addr.(netapi.Address)
	if !ok {
		return addr.String()
	}
	key := a.Comparable()
	if p.lastReply == "" || key != p.lastReplyKey {
		p.lastReplyKey, p.lastReply = key, a.String()
	}
	return p.lastReply
}

func (p *serverPacketConn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	close(p.done)
	p.stop()
	for {
		select {
		case packet := <-p.packets:
			pool.PutBytes(packet.data)
		default:
			return nil
		}
	}
}
