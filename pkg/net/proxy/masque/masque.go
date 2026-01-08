package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Masque struct {
	netapi.EmptyDispatch
	p              netapi.Proxy
	TlsConfig      *tls.Config
	addr           *net.UDPAddr
	localAddresses []netip.Prefix
	mtu            int

	ctx    context.Context
	cancel context.CancelFunc
	dev    *wireguard.NetTun
	once   sync.Once

	receive chan []byte
	send    chan []byte

	happyDialer *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
}

func NewMasque(p netapi.Proxy, tlsConfig *tls.Config, addr *net.UDPAddr, localAddresses []netip.Prefix, mtu int) (*Masque, error) {
	dev, err := wireguard.CreateNetTUN(localAddresses, mtu)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	z := &Masque{
		ctx:            ctx,
		cancel:         cancel,
		p:              p,
		TlsConfig:      tlsConfig,
		addr:           addr,
		localAddresses: localAddresses,
		mtu:            mtu,
		dev:            dev,
		receive:        make(chan []byte, 100),
		send:           make(chan []byte, 100),
		happyDialer: dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
			return dev.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
		},
			dialer.WithHappyEyeballsSemaphore[*gonet.TCPConn](semaphore.NewEmptySemaphore())),
	}

	go z.Forward()

	return z, nil
}

type Conn struct {
	packetConn net.PacketConn
	quicConn   *quic.Conn
	tr         *http3.Transport
	h3conn     *http3.ClientConn
	ipconn     *connectip.Conn
}

func (c *Conn) Close() error {
	var err error
	if c.ipconn != nil {
		if er := c.ipconn.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if c.h3conn != nil {
		if er := c.h3conn.CloseWithError(http3.ErrCodeNoError, ""); er != nil {
			err = errors.Join(err, er)
		}
	}

	if c.tr != nil {
		if er := c.tr.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if c.quicConn != nil {
		if er := c.quicConn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), ""); er != nil {
			err = errors.Join(err, er)
		}
	}

	if c.packetConn != nil {
		if er := c.packetConn.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func (m *Masque) Connect(ctx context.Context) (*Conn, error) {
	mConn := &Conn{}

	conn, err := dialer.ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, err
	}

	mConn.packetConn = conn

	quicConn, err := quic.Dial(ctx, conn, m.addr, m.TlsConfig, &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: 1242,
		KeepAlivePeriod:   time.Second * 30,
	})
	if err != nil {
		_ = mConn.Close()
		return nil, err
	}

	mConn.quicConn = quicConn

	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// official client still sends this out as well, even though
			// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
			0x276: 1,
		},
		DisableCompression: true,
	}

	mConn.tr = tr

	hconn := tr.NewClientConn(quicConn)

	mConn.h3conn = hconn

	ipConn, resp, err := Dial(ctx, hconn, ConnectURI, "cf-connect-ip")
	if err != nil {
		_ = mConn.Close()
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return nil, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	err = ipConn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom4([4]byte{}),
			EndIP:      netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		},
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom16([16]byte{}),
			EndIP: netip.AddrFrom16([16]byte{
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
			}),
		},
	})
	if err != nil {
		_ = mConn.Close()
		return nil, err
	}

	mConn.ipconn = ipConn

	if resp.StatusCode != http.StatusOK {
		_ = mConn.Close()
		return nil, fmt.Errorf("failed to dial connect-ip: %v", resp.Status)
	}

	return mConn, nil
}

func (m *Masque) Forward() {
	go func() {
		for {
			select {
			case b := <-m.receive:
				_, err := m.dev.Write([][]byte{b}, 0)
				pool.PutBytes(b)
				if err != nil {
					log.Error("write packet to virtual device failed", "err", err)
				}
			case <-m.ctx.Done():
				return
			}
		}
	}()

	go func() {
		sizeBuf := []int{0}
		devBuf := make([][]byte, 1)

		for {
			buf := pool.GetBytes(m.mtu)
			devBuf[0] = buf

			n, err := m.dev.Read(devBuf, sizeBuf, 0)
			if err != nil {
				pool.PutBytes(buf)
				log.Error("read packet from virtual device failed", "err", err)
				break
			}

			if n == 0 {
				pool.PutBytes(buf)
				continue
			}

			select {
			case m.send <- devBuf[0][:sizeBuf[0]]:
			case <-m.ctx.Done():
				pool.PutBytes(buf)
				return
			}
		}
	}()
}

func (m *Masque) Start() error {
	conn, err := m.Connect(m.ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Warn("failed to close connection", "err", err)
		}
	}()

	ctx, cancel := context.WithCancel(m.ctx)
	defer cancel()

	go func() {
		defer cancel()

		for {
			buf := pool.GetBytes(m.mtu)
			n, err := conn.ipconn.ReadPacket(buf)
			if err != nil {
				pool.PutBytes(buf)
				if errors.As(err, new(*connectip.CloseError)) {
					log.Error("connection closed while reading from IP connection", "err", err)
					return
				}

				log.Warn("Error reading from IP connection, continuing...", "err", err)
				continue
			}

			select {
			case m.receive <- buf[:n]:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case buf := <-m.send:
			icmp, err := conn.ipconn.WritePacket(buf)
			pool.PutBytes(buf)
			if err != nil {
				if errors.As(err, new(*connectip.CloseError)) {
					log.Warn("connection closed while writing to IP connection", "err", err)
					return err
				}

				log.Warn("Error writing to IP connection, continuing...", "err", err)
				continue
			}

			if len(icmp) > 0 {
				select {
				case m.receive <- icmp:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
}

func (m *Masque) init() {
	m.once.Do(func() {
		go func() {
			for {
				select {
				case <-m.ctx.Done():
					return
				default:
				}

				if err := m.Start(); err != nil {
					log.Error("start masque failed", "err", err)
				}

				log.Info("check masque disconnected, retrying in 5 seconds")

				time.Sleep(time.Second * 5)
			}
		}()
	})
}

func (m *Masque) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	m.init()

	conn, err := m.happyDialer.DialHappyEyeballsv2(ctx, addr)
	if err != nil {
		return nil, err
	}

	return wireguard.NewWrapGoNetTcpConn(conn), nil
}

func (m *Masque) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	pc, err := m.dev.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}

	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(context.Background()), pc), nil
}

func (m *Masque) Close() error {
	m.cancel()
	_ = m.p.Close()
	return m.dev.Close()
}

func (m *Masque) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return 0, nil
}
