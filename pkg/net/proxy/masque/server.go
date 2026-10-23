package masque

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque/connectip"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const defaultServerPath = "/.well-known/masque/ip/*/*/"

type ServerConfig struct {
	Listen          string
	Path            string
	AuthToken       string
	ServerAddresses []string
	ClientAddresses []string
	MTU             int
	MaxSessions     int
}

type Server struct {
	http      *http3.Server
	packet    net.PacketConn
	handler   netapi.Handler
	clientIPs []netip.Prefix
	serverIPs []netip.Prefix
	route     []connectip.IPRoute
	authToken string
	path      string
	mtu       int
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

var _ netapi.Accepter = (*Server)(nil)

func (s *Server) Interface() string { return "masque" }

func parseServerPrefixes(values []string, hostOnly bool) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, errors.New("masque: address list must not be empty")
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil || !p.IsValid() || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() ||
			p.Addr().Zone() != "" || (hostOnly && p.Bits() != p.Addr().BitLen()) {
			return nil, fmt.Errorf("masque: invalid address %q (expected a unicast CIDR%s)", value, map[bool]string{true: " host", false: ""}[hostOnly])
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// NewServer terminates standard CONNECT-IP sessions over HTTP/3. Each session
// gets a separate memory-only stack; packets are never injected into a host TUN.
func NewServer(cfg ServerConfig, tlsConfig *tls.Config, handler netapi.Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("masque: nil handler")
	}
	if tlsConfig == nil || len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil && tlsConfig.GetConfigForClient == nil {
		return nil, errors.New("masque: a TLS server certificate is required")
	}
	if cfg.AuthToken == "" {
		return nil, errors.New("masque: authToken is required (anonymous IP forwarding is disabled)")
	}
	if cfg.Listen == "" {
		return nil, errors.New("masque: listen address is required")
	}
	if cfg.Path == "" {
		cfg.Path = defaultServerPath
	}
	if !strings.HasPrefix(cfg.Path, "/") || strings.ContainsAny(cfg.Path, "?#") {
		return nil, errors.New("masque: path must be an absolute URL path without query or fragment")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.MTU < 1280 || cfg.MTU > 65535 {
		return nil, errors.New("masque: mtu must be 1280..65535")
	}
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 64
	}
	if cfg.MaxSessions < 1 || cfg.MaxSessions > 1024 {
		return nil, errors.New("masque: maxSessions must be 1..1024")
	}
	serverIPs, err := parseServerPrefixes(cfg.ServerAddresses, false)
	if err != nil {
		return nil, fmt.Errorf("masque serverAddresses: %w", err)
	}
	clientIPs, err := parseServerPrefixes(cfg.ClientAddresses, true)
	if err != nil {
		return nil, fmt.Errorf("masque clientAddresses: %w", err)
	}
	for _, clientIP := range clientIPs {
		for _, serverIP := range serverIPs {
			if clientIP.Addr() == serverIP.Addr() {
				return nil, fmt.Errorf("masque: client address %s overlaps the server address", clientIP)
			}
		}
	}
	packet, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("masque: listen: %w", err)
	}
	server := &Server{
		packet: packet, handler: handler,
		clientIPs: clientIPs, serverIPs: serverIPs,
		route: fullIPRoutes(), authToken: cfg.AuthToken, path: cfg.Path,
		mtu: cfg.MTU, slots: make(chan struct{}, cfg.MaxSessions),
		done: make(chan struct{}),
	}
	server.http = &http3.Server{
		TLSConfig:       http3.ConfigureTLSConfig(tlsConfig),
		EnableDatagrams: true,
		QUICConfig:      &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 3 * 60 * 1e9},
		Handler:         http.HandlerFunc(server.serveHTTP),
	}
	go func() {
		defer close(server.done)
		if err := server.http.Serve(packet); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Warn("masque HTTP/3 listener exited", "err", err)
		}
	}()
	return server, nil
}

func fullIPRoutes() []connectip.IPRoute {
	return []connectip.IPRoute{
		{IPProtocol: 0, StartIP: netip.AddrFrom4([4]byte{}), EndIP: netip.AddrFrom4([4]byte{255, 255, 255, 255})},
		{IPProtocol: 0, StartIP: netip.IPv6Unspecified(), EndIP: netip.AddrFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})},
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 3 || r.URL.Path != s.path {
		http.Error(w, "unsupported MASQUE path or HTTP version", http.StatusNotFound)
		return
	}
	// A raw token is accepted only over the TLS-protected HTTP/3 connection.
	provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte(s.authToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	request, err := connectip.ParseProxyRequest(r)
	if err != nil {
		if parseErr, ok := errors.AsType[*connectip.ProxyRequestParseError](err); ok {
			http.Error(w, parseErr.Error(), parseErr.HTTPStatus)
		} else {
			http.Error(w, "invalid CONNECT-IP request", http.StatusBadRequest)
		}
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "too many active MASQUE tunnels", http.StatusServiceUnavailable)
		return
	}
	dev, err := wireguard.CreateLightweightInboundTUN(s.serverIPs, s.mtu)
	if err != nil {
		http.Error(w, "failed to initialize packet stack", http.StatusInternalServerError)
		log.Warn("masque create IP stack", "err", err)
		return
	}
	defer dev.Close()
	flows, err := lightweighttun.NewFromStack(dev.Stack(), s.handler, s.serverIPs, "masque")
	if err != nil {
		http.Error(w, "failed to initialize inbound stack", http.StatusInternalServerError)
		log.Warn("masque accept IP flows", "err", err)
		return
	}
	defer flows.Close()
	ipConn, err := (&connectip.Proxy{}).Proxy(w, request)
	if err != nil {
		log.Warn("masque accept CONNECT-IP", "err", err)
		return
	}
	defer ipConn.Close()
	if err := ipConn.AssignAddresses(s.clientIPs); err != nil {
		return
	}
	if err := ipConn.AdvertiseRoute(s.route); err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go s.sendToClient(ctx, cancel, dev, ipConn)
	for {
		packet, err := ipConn.ReadPacketBuffer()
		if err != nil {
			return
		}
		if err := dev.InjectPacket(packet); err != nil {
			return
		}
	}
}

func (s *Server) sendToClient(ctx context.Context, cancel context.CancelFunc, dev *wireguard.LightweightNetTun, conn *connectip.Conn) {
	defer cancel()
	buf := make([]byte, s.mtu)
	for {
		n, err := dev.ReadPacket(buf)
		if err != nil {
			return
		}
		packet := slices.Clone(buf[:n])
		icmp, err := conn.WritePacket(packet)
		if err != nil {
			return
		}
		if len(icmp) != 0 {
			if err := dev.InjectPacket(icmp); err != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.http.Close(), s.packet.Close())
		<-s.done
	})
	return s.closeErr
}
