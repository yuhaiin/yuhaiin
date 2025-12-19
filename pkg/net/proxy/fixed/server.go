package fixed

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Server struct {
	net.Listener
	net.PacketConn

	host string
	pmu  sync.Mutex
	smu  sync.RWMutex

	control   config.TcpUdpControl
	udpDetect bool
}

func (s *Server) Close() error {
	var err error

	if s.Listener != nil {
		if er := s.Listener.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if s.PacketConn != nil {
		if er := s.PacketConn.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func (s *Server) initPacketConn() error {
	if s.PacketConn != nil {
		return nil
	}

	s.pmu.Lock()
	defer s.pmu.Unlock()

	if s.PacketConn != nil {
		return nil
	}

	p, err := dialer.ListenPacket(context.TODO(), "udp", s.host, dialer.WithListener())
	if err != nil {
		return err
	}

	s.PacketConn = p

	return nil
}

func (s *Server) initStream() (net.Listener, error) {
	s.smu.RLock()
	lis := s.Listener
	s.smu.RUnlock()
	if lis != nil {
		return lis, nil
	}

	s.smu.Lock()
	defer s.smu.Unlock()

	if s.Listener != nil {
		return s.Listener, nil
	}

	lis, err := dialer.ListenContext(context.TODO(), "tcp", s.host)
	if err != nil {
		return nil, err
	}

	s.Listener = lis

	return lis, nil
}

func (s *Server) Packet(ctx context.Context) (net.PacketConn, error) {
	if s.control == config.TcpUdpControl_disable_udp {
		return nil, errors.ErrUnsupported
	}

	if err := s.initPacketConn(); err != nil {
		return nil, err
	}

	if s.udpDetect {
		return newUDPDetectPacketConn(s.PacketConn), nil
	}

	return s.PacketConn, nil
}

func (s *Server) Accept() (net.Conn, error) {
	if s.control == config.TcpUdpControl_disable_tcp {
		return nil, errors.ErrUnsupported
	}

	lis, err := s.initStream()
	if err != nil {
		return nil, err
	}

	return lis.Accept()
}

func (s *Server) Addr() net.Addr {
	if s.control == config.TcpUdpControl_disable_tcp {
		return netapi.EmptyAddr
	}

	lis, err := s.initStream()
	if err != nil {
		return netapi.EmptyAddr
	}

	return lis.Addr()
}

func NewServer(c *config.Tcpudp) (netapi.Listener, error) {
	return &Server{
		host:      c.GetHost(),
		control:   c.GetControl(),
		udpDetect: c.GetUdpHappyEyeballs(),
	}, nil
}

func init() {
	register.RegisterNetwork(NewServer)
}

type packet struct {
	data []byte
	addr net.Addr
}

type udpDetectPacketConn struct {
	net.PacketConn

	ch     chan packet
	ctx    context.Context
	cancel context.CancelFunc
}

func newUDPDetectPacketConn(p net.PacketConn) *udpDetectPacketConn {
	ctx, cancel := context.WithCancel(context.TODO())
	u := &udpDetectPacketConn{
		PacketConn: p,
		ch:         make(chan packet, 100),
		ctx:        ctx,
		cancel:     cancel,
	}

	go u.run()

	return u
}

var (
	detectPacket1 = sha256.Sum256([]byte("IHf41q6V7I4fbyfFy%CR!EE0N7KoR*uXhNas0gmCuZsygRm@Aa4N2RE0aRjpO*nMjB2q^wdkfenxs!5mpOecnZ#y$pVEk1taoH*hazbzgJv4BZzaHFM46vHfZkcUw!8Q"))
	detectPacket2 = sha256.Sum256([]byte("Z@SVy17*3q%2t23p#CfYLNHslW52bCIb9h&PLvCWTYHb5XZ46j@IQcTK!z3KapN5^Df8vuO9GY@BtzEx*rUa5ee!Q$2^gDi5Z92Vp2pVTsfHvx$jd2wEI#g0kHJnHNrK"))
)

func (u *udpDetectPacketConn) run() {
	defer u.Close()
	for {
		select {
		case <-u.ctx.Done():
			return
		default:
		}

		data := pool.GetBytes(configuration.UDPBufferSize.Load())
		n, addr, err := u.PacketConn.ReadFrom(data)
		if err != nil {
			log.Warn("udp read failed", "err", err)
			pool.PutBytes(data)
			continue
		}

		if n == 32 && [32]byte(data[:32]) == detectPacket1 {
			pool.PutBytes(data)
			_, err = u.WriteTo(detectPacket2[:], addr)
			if err != nil {
				log.Warn("udp write failed", "err", err)
			}
			continue
		}

		select {
		case <-u.ctx.Done():
			return
		case u.ch <- packet{
			data: data[:n],
			addr: addr,
		}:
		}
	}
}

func (u *udpDetectPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case <-u.ctx.Done():
		return 0, nil, u.ctx.Err()
	case p := <-u.ch:
		defer pool.PutBytes(p.data)
		return copy(b, p.data), p.addr, nil
	}
}

func (u *udpDetectPacketConn) Close() error {
	u.cancel()
	return u.PacketConn.Close()
}
