package inbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	yhttp "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	yhttp2 "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2/v2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/mock"
	ymux "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mux"
	yproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	redirserver "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reverse"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
)

func listenContract(config contract.Inbound, handler netapi.Handler, ranges [2]netip.Prefix) (netapi.Accepter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if config.Protocol.Type == contract.ProtocolHysteria2 {
		return listenHysteria2(config, handler)
	}

	lis, err := contractNetwork(config)
	if err != nil {
		return nil, err
	}
	for _, transport := range config.Transports {
		lis, err = contractTransport(transport, lis)
		if err != nil {
			closeIfNotNil(lis)
			return nil, err
		}
	}

	server, err := contractProtocol(config.Protocol, lis, handler, ranges)
	if err != nil {
		closeIfNotNil(lis)
		return nil, err
	}
	return server, nil
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

func contractProtocol(config contract.Protocol, lis netapi.Listener, handler netapi.Handler, ranges [2]netip.Prefix) (netapi.Accepter, error) {
	switch config.Type {
	case contract.ProtocolHTTP:
		protocol := config.HTTP
		return yhttp.NewServer(yhttp.ServerConfig{
			Username: protocol.Username,
			Password: protocol.Password,
		}, lis, handler)
	case contract.ProtocolSocks5:
		protocol := config.Socks5
		return socks5.NewServer(socks5.ServerConfig{
			Username: protocol.Username,
			Password: protocol.Password,
			UDP:      protocol.UDP,
		}, lis, handler)
	case contract.ProtocolYuubinsya:
		protocol := config.Yuubinsya
		return yuubinsya.NewServer(yuubinsya.ServerConfig{
			Password:    protocol.Password,
			UDPCoalesce: protocol.UDPCoalesce,
		}, lis, handler)
	case contract.ProtocolMixed:
		protocol := config.Mixed
		return mixed.NewServer(mixed.ServerConfig{
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
	case contract.ProtocolReverseHTTP:
		protocol := config.ReverseHTTP
		tlsConfig := ytls.TLSConfig{}
		if protocol.TLS != nil {
			tlsConfig = clientTLSConfig(*protocol.TLS)
		}
		return reverse.NewHTTPServer(reverse.HTTPServerConfig{
			URL: protocol.URL,
			TLS: tlsConfig,
		}, lis, handler)
	case contract.ProtocolReverseTCP:
		return reverse.NewTCPServer(reverse.TCPServerConfig{
			Host: config.ReverseTCP.Target,
		}, lis, handler)
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

func clientTLSConfig(config contract.ClientTLSConfig) ytls.TLSConfig {
	return ytls.TLSConfig{
		Enable:             config.Enabled,
		ServerNames:        append([]string(nil), config.ServerNames...),
		CACert:             append([][]byte(nil), config.CACertsBase64...),
		InsecureSkipVerify: config.InsecureSkipVerify,
		NextProtos:         append([]string(nil), config.NextProtos...),
		ECHConfig:          append([]byte(nil), config.ECHConfigBase64...),
	}
}

func tunConfig(config contract.TunProtocol) device.TunConfig {
	return device.TunConfig{
		AutoFakeIPRoute: config.AutoFakeIPRoute,
		Name:            config.Name,
		MTU:             config.MTU,
		ForceFakeIP:     config.ForceFakeIP,
		SkipMulticast:   config.SkipMulticast,
		Driver:          device.Driver(config.Driver),
		Portal:          config.Portal,
		PortalV6:        config.PortalV6,
		Routes:          append(append([]string(nil), config.Routes...), config.Excludes...),
		PostUp:          append([]string(nil), config.PostUp...),
		PostDown:        append([]string(nil), config.PostDown...),
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
func listenHysteria2(config contract.Inbound, handler netapi.Handler) (netapi.Accepter, error) {
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
	server, err := hysteria2.NewServer(*config.Protocol.Hysteria2, tlsConfig, lis, handler)
	if err != nil {
		closeIfNotNil(lis)
	}
	return server, err
}
