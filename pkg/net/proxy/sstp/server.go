package sstp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/sstp/wire"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/mschap"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/ppp"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
)

const (
	maxSSTPHeader    = 16384
	handshakeTimeout = 20 * time.Second
)

// ServerUser is an MS-CHAPv2 credential. The server needs the actual password
// (or an equivalent NT hash), not an Argon2/bcrypt application-login hash.
type ServerUser struct {
	Username string
	Password string
}

// ServerConfig controls the rootless IPv4 SSTP listener. Addresses are host
// addresses, not subnets; each active session reserves one client address.
type ServerConfig struct {
	ServerAddress   string
	ClientAddresses []string
	DNS             string
	MTU             int
	MaxSessions     int
	Users           []ServerUser
}

type Server struct {
	listener  net.Listener
	tlsConfig *tls.Config
	handler   netapi.Handler
	serverIP  netip.Addr
	dns       net.IP
	mtu       int
	users     map[string]string
	available chan netip.Addr
	done      chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	once      sync.Once
	err       error
}

var _ netapi.Accepter = (*Server)(nil)

func (s *Server) Interface() string { return "sstp" }

// NewServer accepts SSTP connections without installing routes or host TUNs.
// Each established PPP session gets a separate lightweight IP stack.
func NewServer(cfg ServerConfig, tlsConfig *tls.Config, listener net.Listener, handler netapi.Handler) (*Server, error) {
	if handler == nil || listener == nil {
		return nil, errors.New("sstp: listener and handler are required")
	}
	if tlsConfig == nil || len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil {
		return nil, errors.New("sstp: a TLS server certificate is required")
	}
	serverIP, err := netip.ParseAddr(cfg.ServerAddress)
	if err != nil || !serverIP.Is4() || !serverIP.IsGlobalUnicast() {
		return nil, errors.New("sstp: serverAddress must be a unicast IPv4 address")
	}
	if len(cfg.ClientAddresses) == 0 {
		return nil, errors.New("sstp: clientAddresses must not be empty")
	}
	if len(cfg.ClientAddresses) > 1024 {
		return nil, errors.New("sstp: too many client addresses")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	if cfg.MTU < 576 || cfg.MTU > 4000 {
		return nil, errors.New("sstp: MTU must be 576..4000")
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = len(cfg.ClientAddresses)
	}
	if cfg.MaxSessions < 1 || cfg.MaxSessions > len(cfg.ClientAddresses) {
		return nil, errors.New("sstp: maxSessions must be within the address pool size")
	}
	users := make(map[string]string, len(cfg.Users))
	for _, u := range cfg.Users {
		if u.Username == "" || u.Password == "" || len(u.Username) > 256 {
			return nil, errors.New("sstp: each user requires a username and password")
		}
		if _, duplicate := users[u.Username]; duplicate {
			return nil, errors.New("sstp: duplicate username")
		}
		users[u.Username] = u.Password
	}
	if len(users) == 0 {
		return nil, errors.New("sstp: at least one user is required")
	}
	var dns net.IP
	if cfg.DNS != "" {
		addr, err := netip.ParseAddr(cfg.DNS)
		if err != nil || !addr.Is4() {
			return nil, errors.New("sstp: DNS must be an IPv4 address")
		}
		b := addr.As4()
		dns = net.IP(b[:])
	}
	available := make(chan netip.Addr, len(cfg.ClientAddresses))
	seen := make(map[netip.Addr]bool)
	for _, value := range cfg.ClientAddresses {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() || addr == serverIP || seen[addr] {
			return nil, fmt.Errorf("sstp: invalid or duplicate client address %q", value)
		}
		seen[addr] = true
		available <- addr
	}
	config := tlsConfig.Clone()
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
	}
	s := &Server{
		listener: listener, tlsConfig: config, handler: handler, serverIP: serverIP,
		dns: dns, mtu: cfg.MTU, users: users, available: available,
		done: make(chan struct{}), conns: make(map[net.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop(cfg.MaxSessions)
	return s, nil
}

func (s *Server) acceptLoop(maxSessions int) {
	defer s.wg.Done()
	slots := make(chan struct{}, maxSessions)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Warn("sstp listener stopped", "err", err)
			}
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		select {
		case ip := <-s.available:
			s.mu.Lock()
			s.conns[conn] = struct{}{}
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() {
					s.mu.Lock()
					delete(s.conns, conn)
					s.mu.Unlock()
					s.available <- ip
					<-slots
				}()
				if err := s.serve(conn, ip); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					log.Debug("sstp session ended", "err", err)
				}
			}()
		default:
			<-slots
			_ = conn.Close()
		}
	}
}

func (s *Server) Close() error {
	s.once.Do(func() {
		s.err = s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		close(s.done)
	})
	return s.err
}

type serverLink struct {
	conn          *tls.Conn
	writeMu       sync.Mutex
	server        *Server
	clientIP      netip.Addr
	nonce         [wire.NonceLen]byte
	certDER       []byte
	hlak          [mschap.HLAKLen]byte
	authenticated bool
	bound         bool
	up            bool
	device        *wireguard.LightweightNetTun
	flows         netapi.Accepter
	pumpDone      chan struct{}
}

func (l *serverLink) SendPPP(frame []byte) error {
	pkt, err := wire.EncodeData(frame)
	if err != nil {
		return err
	}
	return l.writePacket(pkt)
}

func (l *serverLink) writePacket(pkt []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if err := l.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := l.conn.Write(pkt)
	return err
}

func (l *serverLink) ServerAuthenticated(_ string, password string, ntResponse [mschap.NTResponseLen]byte) {
	l.hlak = mschap.ClientHLAK(password, ntResponse)
	l.authenticated = true
}
func (l *serverLink) ServerNetworkUp() { l.up = true }

func (l *serverLink) close() {
	_ = l.conn.Close()
	if l.flows != nil {
		_ = l.flows.Close()
	}
	if l.device != nil {
		_ = l.device.Close()
	}
	if l.pumpDone != nil {
		<-l.pumpDone
	}
}

func (s *Server) serve(raw net.Conn, clientIP netip.Addr) error {
	defer raw.Close()
	// Select the certificate per connection so the binding hashes the
	// certificate actually presented to this SSTP client.
	cfg := s.tlsConfig.Clone()
	getter := cfg.GetCertificate
	var certDER []byte
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var cert *tls.Certificate
		var err error
		if getter != nil {
			cert, err = getter(hello)
		} else if len(cfg.Certificates) > 0 {
			cert = &cfg.Certificates[0]
		}
		if err != nil {
			return nil, err
		}
		if cert == nil || len(cert.Certificate) == 0 {
			return nil, errors.New("sstp: missing server certificate")
		}
		certDER = cert.Certificate[0]
		return cert, nil
	}
	conn := tls.Server(raw, cfg)
	if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	if err := conn.Handshake(); err != nil {
		return err
	}
	if err := acceptSSTPHTTP(conn); err != nil {
		return err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return err
	}
	link := &serverLink{conn: conn, server: s, clientIP: clientIP, certDER: certDER}
	defer link.close()
	if _, err := rand.Read(link.nonce[:]); err != nil {
		return err
	}
	// The first SSTP packet must be a valid PPP CallConnectRequest.
	control, body, err := wire.ReadPacket(conn)
	if err != nil {
		return err
	}
	if !control {
		return errors.New("sstp: expected CallConnectRequest")
	}
	msg, err := wire.ParseControl(body)
	if err != nil {
		return err
	}
	attr, ok := msg.Attribute(wire.AttrEncapsulatedProtocolID)
	if msg.Type != wire.MsgCallConnectRequest || !ok || !bytes.Equal(attr.Value, []byte{0, wire.ProtocolPPP}) {
		return errors.New("sstp: unsupported encapsulated protocol")
	}
	bindingRequest := make([]byte, 4+wire.NonceLen)
	bindingRequest[3] = wire.CertHashSHA256
	copy(bindingRequest[4:], link.nonce[:])
	ack, err := wire.EncodeControl(wire.MsgCallConnectAck, []wire.Attribute{{ID: wire.AttrCryptoBindingReq, Value: bindingRequest}})
	if err != nil {
		return err
	}
	if err := link.writePacket(ack); err != nil {
		return err
	}

	sv4 := s.serverIP.As4()
	cv4 := clientIP.As4()
	p, err := ppp.NewServer(net.IP(sv4[:]), net.IP(cv4[:]), s.dns, func(user string) (string, bool) {
		password, ok := s.users[user]
		return password, ok
	}, link, link)
	if err != nil {
		return err
	}
	if err := p.Start(); err != nil {
		return err
	}
	if err := raw.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	for {
		control, body, err := wire.ReadPacket(conn)
		if err != nil {
			return err
		}
		if control {
			msg, err := wire.ParseControl(body)
			if err != nil {
				return err
			}
			switch msg.Type {
			case wire.MsgCallConnected:
				if !link.authenticated || link.bound {
					return errors.New("sstp: unexpected CallConnected")
				}
				cb, ok := msg.Attribute(wire.AttrCryptoBinding)
				if !ok || len(cb.Value) != CBValueLen || cb.Value[3] != wire.CertHashSHA256 ||
					subtle.ConstantTimeCompare(cb.Value[4:36], link.nonce[:]) != 1 {
					return errors.New("sstp: invalid crypto binding nonce or hash protocol")
				}
				if err := VerifyCryptoBinding(body, link.hlak, link.certDER); err != nil {
					return err
				}
				link.bound = true
			case wire.MsgEchoRequest:
				echo, err := wire.EncodeControl(wire.MsgEchoResponse, nil)
				if err != nil {
					return err
				}
				if err := link.writePacket(echo); err != nil {
					return err
				}
			case wire.MsgCallDisconnect, wire.MsgCallAbort:
				return io.EOF
			default:
				return fmt.Errorf("sstp: unexpected control message %d", msg.Type)
			}
		} else if packet, ok := ppp.IsIP(body); ok {
			if link.device == nil || !validClientPacket(packet, link.clientIP, s.mtu) {
				return errors.New("sstp: unauthenticated or spoofed IP packet")
			}
			// PPP may pad the information field beyond the IP total length.
			packet = packet[:int(packet[2])<<8|int(packet[3])]
			if err := link.device.InjectPacket(packet); err != nil {
				return err
			}
		} else if err := p.Receive(body); err != nil {
			return err
		}
		if p.Up() && link.bound && link.device == nil {
			if err := link.startData(); err != nil {
				return err
			}
			if err := raw.SetReadDeadline(time.Time{}); err != nil {
				return err
			}
		}
	}
}

func validClientPacket(b []byte, ip netip.Addr, mtu int) bool {
	if len(b) < 20 || b[0]>>4 != 4 || int(b[0]&0xf)*4 < 20 || int(b[0]&0xf)*4 > len(b) {
		return false
	}
	if total := int(b[2])<<8 | int(b[3]); total < int(b[0]&0xf)*4 || total > len(b) || total > mtu {
		return false
	}
	addr := ip.As4()
	return bytes.Equal(b[12:16], addr[:])
}

func (l *serverLink) startData() error {
	addr := netip.PrefixFrom(l.server.serverIP, 32)
	dev, err := wireguard.CreateLightweightInboundTUN([]netip.Prefix{addr}, l.server.mtu)
	if err != nil {
		return err
	}
	l.device = dev
	flows, err := lightweighttun.NewFromStack(dev.Stack(), l.server.handler, []netip.Prefix{addr}, "sstp")
	if err != nil {
		return err
	}
	l.flows = flows
	l.pumpDone = make(chan struct{})
	go func() {
		defer close(l.pumpDone)
		buf := make([]byte, l.server.mtu)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				break
			}
			if err = l.SendPPP(ppp.EncapsulateIP(buf[:n])); err != nil {
				break
			}
		}
		_ = l.conn.Close()
	}()
	return nil
}

func acceptSSTPHTTP(conn io.ReadWriter) error {
	// Avoid a buffered reader: reading past CRLFCRLF would consume SSTP frames.
	header := make([]byte, 0, 512)
	var one [1]byte
	for len(header) < maxSSTPHeader {
		if _, err := io.ReadFull(conn, one[:]); err != nil {
			return err
		}
		header = append(header, one[0])
		if len(header) >= 4 && bytes.Equal(header[len(header)-4:], []byte("\r\n\r\n")) {
			break
		}
	}
	if len(header) < 4 || !bytes.Equal(header[len(header)-4:], []byte("\r\n\r\n")) {
		return errors.New("sstp: HTTP header too large")
	}
	lines := strings.Split(string(header), "\r\n")
	if len(lines) < 2 || lines[0] != "SSTP_DUPLEX_POST "+sstpURI+" HTTP/1.1" {
		return errors.New("sstp: unsupported HTTP request")
	}
	hasLength := false
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") && strings.TrimSpace(value) == "18446744073709551615" {
			hasLength = true
		}
	}
	if !hasLength {
		return errors.New("sstp: invalid content length")
	}
	_, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
	return err
}
