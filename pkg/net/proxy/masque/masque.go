package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque/connectip"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/tailscale/wireguard-go/tun"
)

type Masque struct {
	netapi.EmptyDispatch
	p netapi.Proxy

	ctx       context.Context
	TlsConfig *tls.Config
	addr      *net.UDPAddr
	cancel    context.CancelFunc
	dev       *wireguard.LightweightNetTun

	receive chan []byte
	send    chan []byte

	happyDialer    *dialer.HappyEyeballsv2Dialer[net.Conn]
	localAddresses []netip.Prefix
	mtu            int
	http2          bool
	cloudflare     bool
	requestURL     string
	bearerToken    string

	once sync.Once
}

// Room for the DATAGRAM capsule header and optional IP context ID. It is
// included in queued send buffers and reclaimed with the rest of the buffer.
const packetHeadroom = 16

func NewMasque(p netapi.Proxy, tlsConfig *tls.Config, addr *net.UDPAddr, localAddresses []netip.Prefix, mtu int) (*Masque, error) {
	return NewMasqueWithTransport(p, tlsConfig, addr, localAddresses, mtu, "h3")
}

// NewMasqueWithTransport selects QUIC/HTTP3 with BBR or TCP/HTTP2.
func NewMasqueWithTransport(p netapi.Proxy, tlsConfig *tls.Config, addr *net.UDPAddr, localAddresses []netip.Prefix, mtu int, transport string) (*Masque, error) {
	if transport != "" && transport != "h3" && transport != "h2" {
		return nil, fmt.Errorf("unsupported MASQUE transport %q", transport)
	}
	dev, err := wireguard.CreateLightweightNetTUN(localAddresses, mtu)
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
		http2:          transport == "h2",
		cloudflare:     true,
		requestURL:     ConnectURI + "/",
		dev:            dev,
		receive:        make(chan []byte, 100),
		send:           make(chan []byte, 100),
		happyDialer: dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
			return dev.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
		},
			dialer.WithHappyEyeballsSemaphore[net.Conn](semaphore.NewEmptySemaphore())),
	}

	go z.Forward()

	return z, nil
}

type Conn struct {
	packetConn    net.PacketConn
	quicTransport *quic.Transport
	quicConn      *quic.Conn
	tr            *http3.Transport
	h2            *http2ClientConn
	h3conn        *http3.ClientConn
	ipconn        *connectip.Conn
	cloudflare    bool
}

func (c *Conn) Close() error {
	var err error
	if c.ipconn != nil {
		if er := c.ipconn.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}
	if c.h2 != nil {
		if er := c.h2.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if c.h3conn != nil {
		if er := c.h3conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), ""); er != nil {
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

	if c.quicTransport != nil {
		if er := c.quicTransport.Close(); er != nil {
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

// Connect retries the specific transient HTTP/3 framing failure observed by usque.
// Other failures (especially authentication failures) are returned immediately.
func (m *Masque) Connect(ctx context.Context) (*Conn, error) {
	if m.http2 {
		return m.connectHTTP2(ctx)
	}
	var lastErr error
	for range 2 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := m.connectOnce(ctx)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !isRetryableHTTP3ConnectFailure(err) {
			break
		}
	}
	return nil, lastErr
}

func isRetryableHTTP3ConnectFailure(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "failed to read response") &&
		strings.Contains(message, "PROTOCOL_VIOLATION")
}

func (m *Masque) connectOnce(ctx context.Context) (*Conn, error) {
	mConn := &Conn{cloudflare: m.cloudflare}

	network := "udp4"
	if m.addr.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := dialer.ListenPacket(ctx, network, "", func(o *dialer.Options) { o.PacketConnHintAddress = m.addr })
	if err != nil {
		return nil, err
	}

	mConn.packetConn = conn

	// Cloudflare's MASQUE endpoint intermittently rejects shorter source CIDs.
	// Match the upstream usque transport's 20-byte connection ID.
	cidLength := 12
	if m.cloudflare {
		cidLength = 20
	}
	quicTransport := &quic.Transport{Conn: conn, ConnectionIDLength: cidLength}
	mConn.quicTransport = quicTransport
	quicConn, err := quicTransport.Dial(ctx, m.addr, m.TlsConfig, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		_ = mConn.Close()
		return nil, err
	}

	mConn.quicConn = quicConn
	hysteria2.UseBBRForMASQUE(quicConn)

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

	req, err := connectip.NewRequest(ctx, m.requestURL)
	if err != nil {
		_ = mConn.Close()
		return nil, err
	}
	var ipClient *connectip.ClientConn
	if m.cloudflare {
		// Preserve Cloudflare WARP's legacy protocol and draft datagrams.
		req.Header()["User-Agent"] = []string{""}
		ipClient = connectip.NewCloudflareClientConn(hconn, quicConn)
	} else {
		if m.bearerToken != "" {
			req.Header().Set("Authorization", "Bearer "+m.bearerToken)
		}
		ipClient = connectip.NewClientConn(hconn)
	}
	ipConn, resp, err := ipClient.Dial(req)
	if err != nil {
		_ = mConn.Close()
		if strings.Contains(err.Error(), "tls: access denied") {
			return nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return nil, fmt.Errorf("failed to dial connect-ip: %w", err)
	}
	return finishMasqueConnect(mConn, ipConn, resp)
}

func finishMasqueConnect(mConn *Conn, ipConn *connectip.Conn, resp *http.Response) (*Conn, error) {
	mConn.ipconn = ipConn
	if resp.StatusCode != http.StatusOK {
		_ = mConn.Close()
		return nil, fmt.Errorf("failed to dial connect-ip: %s", resp.Status)
	}
	routes := []connectip.IPRoute{
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
	}
	var err error
	if mConn.h2 != nil || !mConn.cloudflare {
		err = ipConn.SetLocalRoutes(routes)
	} else {
		err = ipConn.AdvertiseRoute(routes)
	}
	if err != nil {
		_ = mConn.Close()
		return nil, err
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
		packets := make([]tun.ReadPacket, m.dev.BatchSize())
		slab := make([]byte, m.mtu+2*tun.ReadPacketSpacing)

		for {
			n, err := m.dev.Read(slab, packets)
			if err != nil {
				log.Error("read packet from virtual device failed", "err", err)
				break
			}

			if n == 0 {
				continue
			}

			packet := packets[0]
			buf := pool.GetBytes(packetHeadroom + packet.Size)
			copy(buf[packetHeadroom:], slab[packet.Offset:packet.Offset+packet.Size])
			select {
			case m.send <- buf:
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
			packet, err := conn.ipconn.ReadPacketBuffer()
			if err != nil {
				if _, ok := errors.AsType[*connectip.CloseError](err); ok {
					log.Error("connection closed while reading from IP connection", "err", err)
					return
				}

				// Receive errors are not necessarily transient. Reconnect instead
				// of spinning forever on a dead QUIC session.
				if ctx.Err() == nil {
					log.Warn("reading from IP connection failed, reconnecting", "err", err)
				}
				return
			}

			// The configured MTU limits local transmission, not peer packet
			// sizes. Clone only the actual packet into pooled queue storage.
			buf := pool.Clone(packet)
			select {
			case m.receive <- buf:
			case <-ctx.Done():
				pool.PutBytes(buf)
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case buf := <-m.send:
			icmp, err := conn.ipconn.WritePacketBuffer(buf, packetHeadroom, len(buf)-packetHeadroom)
			pool.PutBytes(buf)
			if err != nil {
				if _, ok := errors.AsType[*connectip.CloseError](err); ok {
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

				select {
				case <-m.ctx.Done():
					return
				case <-time.After(5 * time.Second):
					log.Info("masque reconnecting")
				}
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

	return conn, nil
}

func (m *Masque) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	if err := m.ctx.Err(); err != nil {
		return nil, net.ErrClosed
	}
	m.init()
	pc, err := m.dev.DialUDP(nil, nil)
	if err != nil {
		return nil, err
	}

	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), pc), nil
}

func (m *Masque) Close() error {
	m.cancel()
	_ = m.p.Close()
	return m.dev.Close()
}

func (m *Masque) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return 0, nil
}
