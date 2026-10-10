package globalprotect

import (
 "context"
 "crypto/tls"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "net/url"
 "sync"
 "sync/atomic"
 "time"

 contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
 "github.com/Asutorufa/yuhaiin/pkg/log"
 "github.com/Asutorufa/yuhaiin/pkg/net/dialer"
 "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
 "github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
 "github.com/Asutorufa/yuhaiin/pkg/register"
 "github.com/tailscale/wireguard-go/tun"
 "gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Client struct {
 netapi.EmptyDispatch
 control *control
 session session
 tunnel *wireguard.NetTun
 conn *tls.Conn
 ctx context.Context
 cancel context.CancelFunc
 closeOnce sync.Once
 writeMu sync.Mutex
 dpdPending atomic.Bool
 closed atomic.Bool
 mu sync.Mutex
 failure error
 dialer *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
 mtu int
}

var _ netapi.Proxy = (*Client)(nil)

func init() {
 register.RegisterContractPoint("globalprotect", func(config contractnode.GlobalProtect, p netapi.Proxy) (netapi.Proxy, error) {
  return NewClient(Config{
   Gateway: config.Gateway, Username: config.Username, Password: config.Password,
   Computer: config.Computer, CACertPEM: config.CACertPEM, MTU: int(config.MTU),
  }, p)
 })
}

// NewClient connects to a directly addressed GlobalProtect gateway with
// username/password auth. Portal gateway discovery and interactive auth are
// intentionally not attempted.
func NewClient(config Config, _ netapi.Proxy) (_ netapi.Proxy, err error) {
 if config.Username == "" || config.Password == "" {
  return nil, errors.New("globalprotect: username and password required")
 }
 control, err := newControl(config)
 if err != nil { return nil, err }
 defer control.close()
 ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
 defer cancel()

 if err := control.prelogin(ctx); err != nil { return nil, err }
 s, err := control.login(ctx, config.Username, config.Password)
 if err != nil { return nil, err }
 success := false
 defer func() {
  if !success {
   cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
   defer cleanupCancel()
   _ = control.logout(cleanupCtx, s)
  }
 }()
 cfg, addr, err := control.getConfig(ctx, s)
 if err != nil { return nil, err }

 mtu := config.MTU
 if mtu == 0 { mtu = cfg.MTU }
 if mtu == 0 { mtu = defaultMTU }
 if mtu < 576 || mtu > 1500 { return nil, fmt.Errorf("globalprotect: invalid MTU %d", mtu) }

 conn, err := connectTunnel(ctx, control, s, cfg.TunnelURL)
 if err != nil { return nil, err }
 network, err := wireguard.CreateNetTUN([]netip.Prefix{addr}, mtu)
 if err != nil { _ = conn.Close(); return nil, err }

 runCtx, runCancel := context.WithCancel(context.Background())
 client := &Client{
  control: control, session: s, tunnel: network, conn: conn,
  ctx: runCtx, cancel: runCancel, mtu: mtu,
  dialer: dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (*gonet.TCPConn, error) {
   return network.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: int(port)})
  }),
 }
 success = true
 go client.sendPackets()
 go client.receivePackets()
 go client.keepalive()
 if cfg.Timeout > 0 {
  // Until automatic rekey is implemented, never silently keep using an
  // expired authentication session.
  go client.expireAfter(time.Duration(cfg.Timeout) * time.Second)
 }
 return client, nil
}

func connectTunnel(ctx context.Context, c *control, s session, path string) (*tls.Conn, error) {
 u, err := url.Parse(path)
 if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" || u.Path[0] != '/' {
  return nil, errors.New("globalprotect: invalid SSL tunnel path")
 }
 q := u.Query()
 q.Set("user", s.User)
 q.Set("authcookie", s.Cookie)
 u.RawQuery = q.Encode()

 conn, err := c.dialTLS(ctx)
 if err != nil { return nil, err }
 success := false
 defer func() { if !success { _ = conn.Close() } }()
 if deadline, ok := ctx.Deadline(); ok { _ = conn.SetDeadline(deadline) }
 if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: PAN GlobalProtect\r\n\r\n", u.RequestURI(), c.gateway.Host); err != nil {
  return nil, err
 }
 var response [12]byte
 if _, err := io.ReadFull(conn, response[:]); err != nil { return nil, err }
 if string(response[:]) != "START_TUNNEL" { return nil, errors.New("globalprotect: SSL tunnel not accepted by gateway") }
 _ = conn.SetDeadline(time.Time{})
 success = true
 return conn, nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
 if err := c.stateError(); err != nil { return nil, err }
 conn, err := c.dialer.DialHappyEyeballsv2(ctx, addr)
 if err != nil { return nil, err }
 return wireguard.NewWrapGoNetTcpConn(conn), nil
}

func (c *Client) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
 if err := c.stateError(); err != nil { return nil, err }
 conn, err := c.tunnel.DialUDP(nil, nil)
 if err != nil { return nil, err }
 return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx), conn), nil
}

func (c *Client) Ping(context.Context, netapi.Address) (uint64, error) {
 return 0, errors.ErrUnsupported
}

func (c *Client) stateError() error {
 c.mu.Lock()
 defer c.mu.Unlock()
 if c.failure != nil { return c.failure }
 if c.closed.Load() { return net.ErrClosed }
 return nil
}

func (c *Client) fail(err error) {
 if err == nil || c.closed.Load() { return }
 c.mu.Lock()
 if c.failure == nil { c.failure = err }
 c.mu.Unlock()
 log.Warn("globalprotect tunnel ended", "error", err)
 _ = c.Close()
}

func (c *Client) sendFrame(frame []byte) error {
 c.writeMu.Lock()
 defer c.writeMu.Unlock()
 if c.closed.Load() { return net.ErrClosed }
 _, err := c.conn.Write(frame)
 return err
}

func (c *Client) sendPackets() {
 slab := make([]byte, c.mtu + 2*tun.ReadPacketSpacing)
 packets := make([]tun.ReadPacket, 1)
 for {
  n, err := c.tunnel.Read(slab, packets)
  if err != nil { if c.ctx.Err() == nil { c.fail(err) }; return }
  for _, p := range packets[:n] {
   if p.Offset < 0 || p.Size < 1 || p.Offset+p.Size > len(slab) {
    c.fail(errors.New("globalprotect: invalid outgoing packet bounds"))
    return
   }
   frame, err := encodeFrame(slab[p.Offset:p.Offset+p.Size])
   if err == nil { err = c.sendFrame(frame) }
   if err != nil { c.fail(err); return }
  }
 }
}

func (c *Client) receivePackets() {
 for {
  packet, isDPD, err := readFrame(c.conn, c.mtu)
  if err != nil { if c.ctx.Err() == nil { c.fail(err) }; return }
  if isDPD {
   // The gateway's reply to our own ping must not trigger a ping-pong loop.
   if c.dpdPending.Swap(false) { continue }
   if err := c.sendFrame(dpdFrame()); err != nil { c.fail(err); return }
   continue
  }
  if _, err := c.tunnel.Write([][]byte{packet}, 0); err != nil {
   if c.ctx.Err() == nil { c.fail(err) }
   return
  }
 }
}

func (c *Client) keepalive() {
 ticker := time.NewTicker(10*time.Second)
 defer ticker.Stop()
 for {
  select {
  case <-c.ctx.Done(): return
  case <-ticker.C:
   c.dpdPending.Store(true)
   if err := c.sendFrame(dpdFrame()); err != nil { c.fail(err); return }
  }
 }
}

func (c *Client) expireAfter(d time.Duration) {
 timer := time.NewTimer(d)
 defer timer.Stop()
 select {
 case <-timer.C: c.fail(errors.New("globalprotect: gateway tunnel lifetime elapsed (automatic rekey unsupported)"))
 case <-c.ctx.Done():
 }
}

func (c *Client) Close() error {
 c.closeOnce.Do(func() {
  c.closed.Store(true)
  c.cancel()
  _ = c.conn.Close()
  _ = c.tunnel.Close()
  ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
  defer cancel()
  if err := c.control.logout(ctx, c.session); err != nil {
   log.Debug("globalprotect logout failed", "error", err)
  }
  c.control.close()
 })
 return nil
}
