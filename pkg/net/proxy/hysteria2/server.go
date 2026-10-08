package hysteria2

import (
	"context"
	"crypto/subtle"
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
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	hyserver "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

// Packet IDs must be unique across listeners and reconnects, not just within a
// QUIC connection: the inbound NAT table keys sessions by MigrateID when set.
var packetIDs atomic.Uint64

type Server struct {
	netapi.EmptyInterface
	core      hyserver.Server
	listener  netapi.Listener
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	redirect  io.Closer
}

func NewServer(config contract.Hysteria2Protocol, tlsConfig *tls.Config, lis netapi.Listener, handler netapi.Handler) (*Server, error) {
	if err := validateOptions(config.Auth, config.SalamanderPassword, config.UploadBPS, config.DownloadBPS); err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, errors.New("hysteria2 TLS config is nil")
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
	core, err := hyserver.NewServer(&hyserver.Config{
		Conn:                  packet,
		TLSConfig:             hyserver.TLSConfig{Certificates: tlsConfig.Certificates, GetCertificate: tlsConfig.GetCertificate, ECHKeys: tlsConfig.EncryptedClientHelloKeys},
		Authenticator:         passwordAuth(config.Auth),
		BandwidthConfig:       hyserver.BandwidthConfig{MaxTx: config.UploadBPS, MaxRx: config.DownloadBPS},
		IgnoreClientBandwidth: config.IgnoreClientBandwidth, DisableUDP: config.DisableUDP,
		StreamHandler: func(_ context.Context, meta hyserver.RequestMetadata, stream hyserver.HyStream, target string) {
			addr, err := netapi.ParseAddress("tcp", target)
			if err != nil {
				return
			}
			conn := &streamConn{HyStream: stream, local: meta.Inbound, remote: meta.Source}
			handler.HandleStream(&netapi.StreamMeta{Source: meta.Source, Destination: addr, Inbound: meta.Inbound, Src: conn, Address: addr})
		},
		UDPHandler: func(ctx context.Context, meta hyserver.RequestMetadata, _ string) (hyserver.UDPConn, error) {
			return newServerPacketConn(ctx, meta.Source, handler), nil
		},
	})
	if err != nil {
		if redirect != nil {
			err = errors.Join(err, redirect.Close())
		}
		return nil, err
	}
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

type passwordAuth string

func (p passwordAuth) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return subtle.ConstantTimeCompare([]byte(p), []byte(auth)) == 1, "user"
}

type streamConn struct {
	hyserver.HyStream
	local, remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }

type serverPacketConn struct {
	source  net.Addr
	handler netapi.Handler
	id      uint64
	packets chan datagram
	done    chan struct{}
	mu      sync.Mutex
	closed  bool
	stop    func() bool
}

func newServerPacketConn(ctx context.Context, source net.Addr, handler netapi.Handler) *serverPacketConn {
	p := &serverPacketConn{source: source, handler: handler, id: packetIDs.Add(1), packets: make(chan datagram, 128), done: make(chan struct{})}
	p.mu.Lock()
	p.stop = context.AfterFunc(ctx, func() { _ = p.Close() })
	p.mu.Unlock()
	return p
}

func (p *serverPacketConn) ReadFrom(b []byte) (int, string, error) {
	select {
	case <-p.done:
		return 0, "", net.ErrClosed
	case packet := <-p.packets:
		n := copy(b, packet.data)
		pool.PutBytes(packet.data)
		return n, packet.addr, nil
	}
}

func (p *serverPacketConn) WriteTo(b []byte, target string) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	addr, err := netapi.ParseAddress("udp", target)
	if err != nil {
		return 0, err
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
	case p.packets <- datagram{data, addr.String()}:
	default:
		pool.PutBytes(data)
	}
	return len(b), nil
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
