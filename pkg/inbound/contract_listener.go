package inbound

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	yhttp "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	yhttp2 "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2/v2"
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

func listenContract(config contract.Inbound, handler netapi.Handler, authCenter *auth.Center) (netapi.Accepter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	lis, err := contractNetwork(config)
	if err != nil {
		return nil, err
	}
	for _, transport := range config.Transports {
		lis, err = contractTransport(transport, lis, authCenter)
		if err != nil {
			closeIfNotNil(lis)
			return nil, err
		}
	}

	server, err := contractProtocol(config.Protocol, lis, handler, authCenter)
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

func contractTransport(config contract.Transport, lis netapi.Listener, authCenter *auth.Center) (netapi.Listener, error) {
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
			Password:     legacyAuthString(authCenter, aeadConfig.Password),
			CryptoMethod: aead.CryptoMethod(aeadConfig.CryptoMethod),
			Auth:         authCenter,
		}, lis)
	case contract.TransportProxy:
		return yproxy.NewServer(yproxy.ServerConfig{}, lis)
	default:
		return nil, fmt.Errorf("unsupported contract inbound transport %q", config.Type)
	}
}

func contractProtocol(config contract.Protocol, lis netapi.Listener, handler netapi.Handler, authCenter *auth.Center) (netapi.Accepter, error) {
	basicAuth := authCenter
	if basicAuth != nil && !basicAuth.HasBasicUsers() {
		basicAuth = nil
	}
	usernameAuth := authCenter
	if usernameAuth != nil && !usernameAuth.HasUsernameUsers() {
		usernameAuth = nil
	}
	switch config.Type {
	case contract.ProtocolHTTP:
		protocol := config.HTTP
		return yhttp.NewServer(yhttp.ServerConfig{
			Username: legacyAuthString(authCenter, protocol.Username),
			Password: legacyAuthString(authCenter, protocol.Password),
			Auth:     basicAuth,
		}, lis, handler)
	case contract.ProtocolSocks5:
		protocol := config.Socks5
		return socks5.NewServer(socks5.ServerConfig{
			Username: legacyAuthString(authCenter, protocol.Username),
			Password: legacyAuthString(authCenter, protocol.Password),
			Auth:     basicAuth,
			UDP:      protocol.UDP,
		}, lis, handler)
	case contract.ProtocolYuubinsya:
		protocol := config.Yuubinsya
		return yuubinsya.NewServer(yuubinsya.ServerConfig{
			Password:    legacyAuthString(authCenter, protocol.Password),
			UDPCoalesce: protocol.UDPCoalesce,
			Auth:        authCenter,
		}, lis, handler)
	case contract.ProtocolMixed:
		protocol := config.Mixed
		return mixed.NewServer(mixed.ServerConfig{
			Username: legacyAuthString(authCenter, protocol.Username),
			Password: legacyAuthString(authCenter, protocol.Password),
			Auth:     basicAuth,
		}, lis, handler)
	case contract.ProtocolSocks4A:
		return socks4a.NewServer(socks4a.ServerConfig{
			Username: legacyAuthString(authCenter, config.Socks4A.Username),
			Auth:     usernameAuth,
		}, lis, handler)
	case contract.ProtocolTProxy:
		return contractTProxy(lis, handler)
	case contract.ProtocolRedir:
		return redirserver.NewServer(redirserver.ServerConfig{})(lis, handler)
	case contract.ProtocolTun:
		return tun.NewTun(tunConfig(*config.Tun), lis, handler)
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

func legacyAuthString(center *auth.Center, value string) string {
	if center != nil {
		return ""
	}
	return value
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
		Name:          config.Name,
		MTU:           config.MTU,
		ForceFakeIP:   config.ForceFakeIP,
		SkipMulticast: config.SkipMulticast,
		Driver:        device.Driver(config.Driver),
		Portal:        config.Portal,
		PortalV6:      config.PortalV6,
		Routes:        append(append([]string(nil), config.Routes...), config.Excludes...),
		PostUp:        append([]string(nil), config.PostUp...),
		PostDown:      append([]string(nil), config.PostDown...),
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
