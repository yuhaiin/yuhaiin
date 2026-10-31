package inbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	yhttp "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	yhttp2 "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2/v2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2"
	krunletserver "github.com/Asutorufa/yuhaiin/pkg/net/proxy/krunlet"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/mock"
	ymux "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mux"
	yproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	redirserver "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/sstp"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func listenContract(config contract.Inbound, handler netapi.Handler, ranges [2]netip.Prefix, providers ...proxyauth.Provider) (result netapi.Accepter, resultErr error) {
	var provider proxyauth.Provider
	if len(providers) > 0 {
		provider = providers[0]
	}
	var verifier func(string) proxyauth.Verifier
	var scope *proxyauth.Scope
	if err := config.Validate(); err != nil {
		return nil, err
	}
	defer func() {
		if scope != nil {
			if resultErr != nil {
				scope.Close()
			} else {
				result = &authenticatedAccepter{Accepter: result, scope: scope}
			}
		}
	}()
	if config.Authentication.EffectiveMode() != "legacy" {
		if provider == nil {
			return nil, errors.New("inbound user authentication requires the identity module")
		}
		scope = proxyauth.NewScope()
		verifier = func(protocol string) proxyauth.Verifier {
			return scope.Wrap(provider.Verifier(config.ID, protocol, config.Authentication.Users))
		}
	}
	if config.Authentication.EffectiveMode() == "users" {
		config.Protocol = withoutLegacyAuthentication(config.Protocol)
	}
	if !slices.Contains(Capabilities().Protocols, config.Protocol.Type) {
		return nil, fmt.Errorf("inbound protocol %q is not supported on %s", config.Protocol.Type, Capabilities().Platform)
	}

	if config.Protocol.Type == contract.ProtocolHysteria2 {
		return listenHysteria2(config, handler, verifier)
	}
	if config.Protocol.Type == contract.ProtocolMasque {
		if config.Authentication != nil {
			return nil, errors.New("masque: use authToken; user-scoped authentication is not supported yet")
		}
		return listenMasque(config, handler)
	}
	if config.Protocol.Type == contract.ProtocolWireguard {
		if config.Network.Type != contract.NetworkEmpty || len(config.Transports) != 0 {
			return nil, errors.New("wireguard inbound requires empty network without transports")
		}
		p := config.Protocol.Wireguard
		return wireguard.NewServer(wireguard.ServerConfig{
			PrivateKey: p.PrivateKey, ListenPort: p.ListenPort,
			Addresses: p.Addresses, MTU: p.MTU,
			Peers: toWireguardPeers(p.Peers),
		}, handler)
	}
	if config.Protocol.Type == contract.ProtocolSSTP {
		if config.Network.Type != contract.NetworkTCPUDP || len(config.Transports) != 0 || config.Network.TCPUDP == nil {
			return nil, errors.New("sstp inbound requires a TCP listener and no additional transports")
		}
		if config.Network.TCPUDP.UDP != contract.UDPDisabled && config.Network.TCPUDP.UDP != contract.UDPTCPOnly {
			return nil, errors.New("sstp inbound requires TCP-only networking")
		}
		if _, ok := provider.(proxyauth.MSCHAPv2Provider); !ok {
			return nil, errors.New("sstp requires MS-CHAPv2-capable identity provider")
		}
	}
	if config.Protocol.Type == contract.ProtocolKrunlet {
		if config.Network.Type != contract.NetworkEmpty {
			return nil, errors.New("krunlet inbound requires empty network")
		}
		for _, transport := range config.Transports {
			if transport.Type != contract.TransportNormal {
				return nil, errors.New("krunlet inbound does not support additional transports")
			}
		}
		return krunletserver.NewServer(config.Protocol.Krunlet.Socket, handler)
	}

	lis, err := contractNetwork(config)
	if err != nil {
		return nil, err
	}
	if binder, ok := lis.(interface{ Bind() error }); ok {
		if err := binder.Bind(); err != nil {
			closeIfNotNil(lis)
			return nil, fmt.Errorf("bind inbound listener: %w", err)
		}
	}
	var bindings []contract.RuntimeListener
	if bound, ok := lis.(interface{ BoundAddresses() []net.Addr }); ok {
		for _, address := range bound.BoundAddresses() {
			bindings = append(bindings, contract.RuntimeListener{Kind: address.Network(), Listen: address.String()})
		}
	}
	for _, transport := range config.Transports {
		lis, err = contractTransport(transport, lis)
		if err != nil {
			closeIfNotNil(lis)
			return nil, err
		}
	}

	var sstpVerifier proxyauth.MSCHAPv2Verifier
	if config.Protocol.Type == contract.ProtocolSSTP {
		mschapProvider := provider.(proxyauth.MSCHAPv2Provider)
		sstpVerifier = scope.WrapMSCHAPv2(mschapProvider.MSCHAPv2Verifier(config.ID, config.Authentication.Users))
	}
	server, err := contractProtocol(config.Protocol, lis, handler, ranges, verifier, sstpVerifier)
	if err != nil {
		closeIfNotNil(lis)
		return nil, err
	}
	if len(bindings) > 0 {
		return &boundAccepter{Accepter: server, bindings: bindings}, nil
	}
	return server, nil
}

type authenticatedAccepter struct {
	netapi.Accepter
	scope *proxyauth.Scope
}

func (s *authenticatedAccepter) Close() error { s.scope.Close(); return s.Accepter.Close() }
func (s *authenticatedAccepter) listenerBindings() []contract.RuntimeListener {
	if reporter, ok := s.Accepter.(interface {
		listenerBindings() []contract.RuntimeListener
	}); ok {
		return reporter.listenerBindings()
	}
	return nil
}

func toWireguardPeers(peers []contract.WireguardPeer) []wireguard.ServerPeer {
	out := make([]wireguard.ServerPeer, 0, len(peers))
	for _, p := range peers {
		out = append(out, wireguard.ServerPeer{PublicKey: p.PublicKey, PreSharedKey: p.PreSharedKey, AllowedIPs: p.AllowedIPs})
	}
	return out
}

type boundAccepter struct {
	netapi.Accepter
	bindings []contract.RuntimeListener
}

func (s *boundAccepter) listenerBindings() []contract.RuntimeListener {
	return slices.Clone(s.bindings)
}

func contractNetwork(config contract.Inbound) (netapi.Listener, error) {
	switch config.Network.Type {
	case contract.NetworkEmpty:
		return contractProtocolNetwork(config.Protocol)
	case contract.NetworkTCPUDP:
		network := config.Network.TCPUDP
		return fixed.NewServer(fixed.ServerConfig{
			Host:    network.Host,
			Control: contractUDPControl(network.UDP),
		})
	case contract.NetworkQUIC:
		network := config.Network.QUIC
		tlsConfig := ytls.ServerConfig{}
		if network.TLS != nil {
			tlsConfig = serverTLSConfig(*network.TLS)
		}
		return quic.NewServer(quic.ServerConfig{
			Host: network.Host,
			TLS:  tlsConfig,
		})
	default:
		return nil, fmt.Errorf("unsupported contract inbound network %q", config.Network.Type)
	}
}

func contractProtocolNetwork(protocol contract.Protocol) (netapi.Listener, error) {
	switch protocol.Type {
	case contract.ProtocolRedir:
		return fixed.NewServer(fixed.ServerConfig{
			Host:    protocol.Redir.Host,
			Control: fixed.ControlDisableUDP,
		})
	case contract.ProtocolTProxy:
		return fixed.NewServer(fixed.ServerConfig{
			Host:    protocol.TProxy.Host,
			Control: fixed.ControlAll,
		})
	case contract.ProtocolTun:
		return nil, nil
	default:
		return nil, nil
	}
}

func contractUDPControl(mode string) fixed.Control {
	switch mode {
	case contract.UDPTCPOnly, contract.UDPDisabled:
		return fixed.ControlDisableUDP
	case contract.UDPUdpOnly:
		return fixed.ControlDisableTCP
	default:
		return fixed.ControlAll
	}
}

func contractTransport(config contract.Transport, lis netapi.Listener) (netapi.Listener, error) {
	switch config.Type {
	case contract.TransportNormal:
		return lis, nil
	case contract.TransportTLS:
		if config.TLS == nil || config.TLS.TLS == nil {
			return nil, errors.New("tls transport missing tls config")
		}
		return ytls.NewServer(serverTLSConfig(*config.TLS.TLS), lis)
	case contract.TransportMux:
		return ymux.NewServer(ymux.ServerConfig{}, lis)
	case contract.TransportHTTP2:
		return yhttp2.NewServer(yhttp2.ServerConfig{}, lis)
	case contract.TransportWebSocket:
		return websocket.NewServer(websocket.ServerConfig{}, lis)
	case contract.TransportReality:
		realityConfig := config.Reality
		return reality.NewServer(reality.ServerConfig{
			Dest:        realityConfig.Dest,
			ShortID:     realityConfig.ShortIDs,
			ServerName:  realityConfig.ServerNames,
			PrivateKey:  realityConfig.PrivateKey,
			MLDSA65Seed: realityConfig.MLDSA65Seed,
			Debug:       realityConfig.Debug,
		}, lis)
	case contract.TransportTLSAuto:
		tlsAuto := config.TLSAuto
		var ech ytls.TlsAutoECH
		if tlsAuto.ECH != nil {
			ech = ytls.TlsAutoECH{
				Enable:     tlsAuto.ECH.Enabled,
				Config:     tlsAuto.ECH.ConfigBase64,
				PrivateKey: tlsAuto.ECH.PrivateKeyBase64,
			}
		}
		return ytls.NewTlsAutoServer(ytls.TlsAutoServerConfig{
			CACert:      tlsAuto.CACertBase64,
			CAKey:       tlsAuto.CAKeyBase64,
			NextProtos:  tlsAuto.NextProtos,
			ServerNames: tlsAuto.ServerNames,
			ECH:         ech,
		}, lis)
	case contract.TransportHTTPMock:
		return mock.NewServer(mock.ServerConfig{}, lis)
	case contract.TransportAEAD:
		aeadConfig := config.AEAD
		return aead.NewServer(aead.Config{
			Password:     aeadConfig.Password,
			CryptoMethod: aead.CryptoMethod(aeadConfig.CryptoMethod),
		}, lis)
	case contract.TransportProxy:
		return yproxy.NewServer(yproxy.ServerConfig{}, lis)
	default:
		return nil, fmt.Errorf("unsupported contract inbound transport %q", config.Type)
	}
}

func contractProtocol(config contract.Protocol, lis netapi.Listener, handler netapi.Handler, ranges [2]netip.Prefix, verifier func(string) proxyauth.Verifier, sstpVerifier proxyauth.MSCHAPv2Verifier) (netapi.Accepter, error) {
	verify := func(protocol string) proxyauth.Verifier {
		if verifier != nil {
			return verifier(protocol)
		}
		return nil
	}
	switch config.Type {
	case contract.ProtocolHTTP:
		protocol := config.HTTP
		return yhttp.NewServer(yhttp.ServerConfig{Authenticate: verify("http"),
			Username: protocol.Username,
			Password: protocol.Password,
		}, lis, handler)
	case contract.ProtocolSocks5:
		protocol := config.Socks5
		return socks5.NewServer(socks5.ServerConfig{Authenticate: verify("socks5"),
			Username: protocol.Username,
			Password: protocol.Password,
			UDP:      protocol.UDP,
		}, lis, handler)
	case contract.ProtocolYuubinsya:
		protocol := config.Yuubinsya
		return yuubinsya.NewServer(yuubinsya.ServerConfig{Authenticate: verify("yuubinsya"),
			Password:    protocol.Password,
			UDPCoalesce: protocol.UDPCoalesce,
		}, lis, handler)
	case contract.ProtocolMixed:
		protocol := config.Mixed
		return mixed.NewServer(mixed.ServerConfig{AuthenticateHTTP: verify("http"), AuthenticateSocks5: verify("socks5"),
			Username: protocol.Username,
			Password: protocol.Password,
		}, lis, handler)
	case contract.ProtocolSocks4A:
		return socks4a.NewServer(socks4a.ServerConfig{
			Username: config.Socks4A.Username,
		}, lis, handler)
	case contract.ProtocolTProxy:
		return contractTProxy(lis, handler)
	case contract.ProtocolRedir:
		return redirserver.NewServer(redirserver.ServerConfig{})(lis, handler)
	case contract.ProtocolTun:
		options := tunConfig(*config.Tun)
		options.FakeIPRanges = ranges
		return tun.NewTun(options, lis, handler)
	case contract.ProtocolSSTP:
		c := config.SSTP
		if c.TLS == nil {
			return nil, errors.New("sstp: TLS configuration is required")
		}
		tlsConfig, err := ytls.ParseServerTLSConfig(serverTLSConfig(*c.TLS))
		if err != nil {
			return nil, err
		}

		return sstp.NewServer(sstp.ServerConfig{
			ServerAddress: c.ServerAddress, ClientAddresses: c.ClientAddresses,
			DNS: c.DNS, MTU: c.MTU, MaxSessions: c.MaxSessions, Authenticate: sstpVerifier,
		}, tlsConfig, lis, handler)
	case contract.ProtocolReverseTCP:
		return newReverseTCPServer(config.ReverseTCP.Target, lis, handler)
	case contract.ProtocolNone:
		return noopAccepter{Listener: lis}, nil
	default:
		return nil, fmt.Errorf("unsupported contract inbound protocol %q", config.Type)
	}
}

func serverTLSConfig(config contract.ServerTLSConfig) ytls.ServerConfig {
	out := ytls.ServerConfig{
		NextProtos:            append([]string(nil), config.NextProtos...),
		Certificates:          make([]ytls.CertificateConfig, 0, len(config.Certificates)),
		ServerNameCertificate: make(map[string]ytls.CertificateConfig, len(config.ServerNameCertificate)),
	}
	for _, cert := range config.Certificates {
		out.Certificates = append(out.Certificates, certificateConfig(cert))
	}
	for name, cert := range config.ServerNameCertificate {
		out.ServerNameCertificate[name] = certificateConfig(cert)
	}
	if len(out.ServerNameCertificate) == 0 {
		out.ServerNameCertificate = nil
	}
	return out
}

func certificateConfig(config contract.Certificate) ytls.CertificateConfig {
	return ytls.CertificateConfig{
		Cert:         config.CertBase64,
		Key:          config.KeyBase64,
		CertFilePath: config.CertFile,
		KeyFilePath:  config.KeyFile,
	}
}

func tunConfig(config contract.TunProtocol) device.TunConfig {
	return device.TunConfig{
		Platform: device.PlatformConfig{Darwin: device.DarwinConfig{
			ExperimentalBatch: config.Darwin.ExperimentalBatch,
			BatchSize:         config.Darwin.BatchSize,
			PendingPackets:    config.Darwin.PendingPackets,
		}},
		Stack:             config.Stack,
		OutputScheduler:   config.OutputScheduler,
		CongestionControl: config.CongestionControl,
		AutoFakeIPRoute:   config.AutoFakeIPRoute,
		Name:              config.Name,
		MTU:               config.MTU,
		ForceFakeIP:       config.ForceFakeIP,
		SkipMulticast:     config.SkipMulticast,
		Driver:            device.Driver(config.Driver),
		Portal:            config.Portal,
		PortalV6:          config.PortalV6,
		Routes:            append(append([]string(nil), config.Routes...), config.Excludes...),
		PostUp:            append([]string(nil), config.PostUp...),
		PostDown:          append([]string(nil), config.PostDown...),
	}
}

func closeIfNotNil(closer interface{ Close() error }) {
	if closer != nil {
		_ = closer.Close()
	}
}

type noopAccepter struct {
	netapi.EmptyInterface
	net.Listener
}

func (n noopAccepter) Close() error {
	if n.Listener != nil {
		return n.Listener.Close()
	}
	return nil
}

func (n noopAccepter) AcceptPacket() (*netapi.Packet, error) {
	return nil, context.Canceled
}

// Hysteria owns QUIC/HTTP3. TLS transports configure its handshake rather than
// wrapping a TCP listener, and the existing quic network uses a different wire format.
func listenHysteria2(config contract.Inbound, handler netapi.Handler, verifiers ...func(string) proxyauth.Verifier) (netapi.Accepter, error) {
	if config.Network.Type != contract.NetworkTCPUDP || config.Network.TCPUDP.UDP != contract.UDPUdpOnly {
		return nil, errors.New("hysteria2 requires tcp_udp network with udp_only")
	}
	var tlsConfig *tls.Config
	for _, transport := range config.Transports {
		if transport.Type == contract.TransportNormal {
			continue
		}
		if tlsConfig != nil {
			return nil, errors.New("hysteria2 requires exactly one TLS or TLS-auto transport")
		}
		var err error
		switch transport.Type {
		case contract.TransportTLS:
			if transport.TLS.TLS == nil {
				return nil, errors.New("hysteria2 missing TLS config")
			}
			tlsConfig, err = ytls.ParseServerTLSConfig(serverTLSConfig(*transport.TLS.TLS))
		case contract.TransportTLSAuto:
			auto := transport.TLSAuto
			if len(auto.ServerNames) == 0 {
				return nil, errors.New("hysteria2 TLS-auto requires serverNames")
			}
			options := ytls.TlsAutoServerConfig{LeafAlgorithm: x509.ECDSA, CACert: auto.CACertBase64, CAKey: auto.CAKeyBase64, ServerNames: auto.ServerNames}
			if auto.ECH != nil {
				options.ECH = ytls.TlsAutoECH{Enable: auto.ECH.Enabled, Config: auto.ECH.ConfigBase64, PrivateKey: auto.ECH.PrivateKeyBase64}
			}
			tlsConfig, err = ytls.NewTLSAutoConfig(options)
		default:
			return nil, fmt.Errorf("hysteria2 does not support transport %q", transport.Type)
		}
		if err != nil {
			return nil, err
		}
	}
	if tlsConfig == nil {
		return nil, errors.New("hysteria2 requires TLS or TLS-auto")
	}
	lis, err := contractNetwork(config)
	if err != nil {
		return nil, err
	}
	server, err := hysteria2.NewServer(*config.Protocol.Hysteria2, tlsConfig, lis, handler, func() proxyauth.Verifier {
		if len(verifiers) > 0 && verifiers[0] != nil {
			return verifiers[0]("hysteria2")
		}
		return nil
	}())
	if err != nil {
		closeIfNotNil(lis)
	}
	return server, err
}

// MASQUE owns the UDP socket and HTTP/3 stack. It must not be layered on the
// app's native QUIC network or arbitrary HTTP/TCP transports.
func listenMasque(config contract.Inbound, handler netapi.Handler) (netapi.Accepter, error) {
	if config.Network.Type != contract.NetworkTCPUDP || config.Network.TCPUDP.UDP != contract.UDPUdpOnly {
		return nil, errors.New("masque requires tcp_udp network with udp_only")
	}
	var tlsConfig *tls.Config
	for _, transport := range config.Transports {
		if transport.Type == contract.TransportNormal {
			continue
		}
		if tlsConfig != nil {
			return nil, errors.New("masque requires exactly one TLS transport")
		}
		if transport.Type != contract.TransportTLS || transport.TLS == nil || transport.TLS.TLS == nil {
			return nil, errors.New("masque requires TLS transport with server certificate")
		}
		var err error
		tlsConfig, err = ytls.ParseServerTLSConfig(serverTLSConfig(*transport.TLS.TLS))
		if err != nil {
			return nil, err
		}
	}
	if tlsConfig == nil {
		return nil, errors.New("masque requires TLS transport")
	}
	p := config.Protocol.Masque
	return masque.NewServer(masque.ServerConfig{
		Listen:          config.Network.TCPUDP.Host,
		Path:            p.Path,
		AuthToken:       p.AuthToken,
		ServerAddresses: p.ServerAddresses,
		ClientAddresses: p.ClientAddresses,
		MTU:             p.MTU,
		MaxSessions:     p.MaxSessions,
	}, tlsConfig, handler)
}
