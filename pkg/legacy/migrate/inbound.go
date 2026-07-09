package migrate

import (
	"fmt"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

type Warning struct {
	Entity  string
	Message string
}

func ConvertLegacyInbound(id string, old *legacy.Inbound) (contract.Inbound, []Warning, error) {
	if old == nil {
		return contract.Inbound{}, nil, fmt.Errorf("legacy inbound %q is nil", id)
	}
	if id == "" {
		id = old.GetName()
	}
	out := contract.Inbound{
		ID:         id,
		Name:       old.GetName(),
		Enabled:    old.GetEnabled(),
		Network:    convertLegacyNetwork(old),
		Transports: make([]contract.Transport, 0, len(old.GetTransport())),
	}
	var warnings []Warning
	if out.Name == "" {
		out.Name = id
	}

	if old.WhichNetwork() == legacy.Inbound_Network_not_set_case {
		warnings = append(warnings, Warning{
			Entity:  id,
			Message: "legacy inbound network is empty; migrated as empty network",
		})
	}

	protocol, err := convertLegacyProtocol(old)
	if err != nil {
		if old.GetEnabled() {
			return contract.Inbound{}, warnings, fmt.Errorf("legacy inbound %q: %w", id, err)
		}
		warnings = append(warnings, Warning{
			Entity:  id,
			Message: err.Error() + "; disabled inbound migrated as none protocol",
		})
		protocol = contract.Protocol{Type: contract.ProtocolNone, None: &contract.NoneProtocol{}}
	}
	out.Protocol = protocol

	for index, oldTransport := range old.GetTransport() {
		if oldTransport.WhichTransport() == legacy.Transport_Transport_not_set_case {
			warnings = append(warnings, Warning{
				Entity:  id,
				Message: fmt.Sprintf("legacy inbound transport[%d] is empty; dropped during migration", index),
			})
			continue
		}
		transport, err := convertLegacyTransport(oldTransport)
		if err != nil {
			return contract.Inbound{}, warnings, fmt.Errorf("legacy inbound %q transport[%d]: %w", id, index, err)
		}
		out.Transports = append(out.Transports, transport)
	}

	if err := out.Validate(); err != nil {
		return contract.Inbound{}, warnings, fmt.Errorf("legacy inbound %q migrated invalid contract: %w", id, err)
	}
	return out, warnings, nil
}

func convertLegacyNetwork(old *legacy.Inbound) contract.Network {
	switch old.WhichNetwork() {
	case legacy.Inbound_Empty_case:
		return contract.Network{Type: contract.NetworkEmpty, Empty: &contract.EmptyNetwork{}}
	case legacy.Inbound_Tcpudp_case:
		tcpudp := old.GetTcpudp()
		return contract.Network{
			Type: contract.NetworkTCPUDP,
			TCPUDP: &contract.TCPUDPNetwork{
				Host: tcpudp.GetHost(),
				UDP:  legacyTCPUDPMode(tcpudp.GetControl()),
			},
		}
	case legacy.Inbound_Quic_case:
		quic := old.GetQuic()
		return contract.Network{
			Type: contract.NetworkQUIC,
			QUIC: &contract.QUICNetwork{
				Host: quic.GetHost(),
				TLS:  convertLegacyServerTLS(quic.GetTls()),
			},
		}
	default:
		return contract.Network{Type: contract.NetworkEmpty, Empty: &contract.EmptyNetwork{}}
	}
}

func legacyTCPUDPMode(control legacy.TcpUdpControl) string {
	switch control {
	case legacy.TcpUdpControl_disable_tcp:
		return contract.UDPUdpOnly
	case legacy.TcpUdpControl_disable_udp:
		return contract.UDPTCPOnly
	case legacy.TcpUdpControl_tcp_udp_control_all:
		return contract.UDPEnabled
	default:
		return contract.UDPEnabled
	}
}

func convertLegacyProtocol(old *legacy.Inbound) (contract.Protocol, error) {
	switch old.WhichProtocol() {
	case legacy.Inbound_Http_case:
		http := old.GetHttp()
		return contract.Protocol{
			Type: contract.ProtocolHTTP,
			HTTP: &contract.HTTPProtocol{
				Username: http.GetUsername(),
				Password: http.GetPassword(),
			},
		}, nil
	case legacy.Inbound_Socks5_case:
		socks5 := old.GetSocks5()
		return contract.Protocol{
			Type: contract.ProtocolSocks5,
			Socks5: &contract.Socks5Protocol{
				Username: socks5.GetUsername(),
				Password: socks5.GetPassword(),
				UDP:      socks5.GetUdp(),
			},
		}, nil
	case legacy.Inbound_Yuubinsya_case:
		yuubinsya := old.GetYuubinsya()
		return contract.Protocol{
			Type: contract.ProtocolYuubinsya,
			Yuubinsya: &contract.YuubinsyaProtocol{
				Password:    yuubinsya.GetPassword(),
				UDPCoalesce: yuubinsya.GetUdpCoalesce(),
			},
		}, nil
	case legacy.Inbound_Mix_case:
		mixed := old.GetMix()
		return contract.Protocol{
			Type: contract.ProtocolMixed,
			Mixed: &contract.MixedProtocol{
				Username: mixed.GetUsername(),
				Password: mixed.GetPassword(),
			},
		}, nil
	case legacy.Inbound_Socks4A_case:
		socks4a := old.GetSocks4A()
		return contract.Protocol{
			Type:    contract.ProtocolSocks4A,
			Socks4A: &contract.Socks4AProtocol{Username: socks4a.GetUsername()},
		}, nil
	case legacy.Inbound_Tproxy_case:
		tproxy := old.GetTproxy()
		return contract.Protocol{
			Type: contract.ProtocolTProxy,
			TProxy: &contract.TProxyProtocol{
				Host:         tproxy.GetHost(),
				DNSHijacking: tproxy.GetDnsHijacking(),
				ForceFakeIP:  tproxy.GetForceFakeip(),
			},
		}, nil
	case legacy.Inbound_Redir_case:
		redir := old.GetRedir()
		return contract.Protocol{
			Type:  contract.ProtocolRedir,
			Redir: &contract.RedirProtocol{Host: redir.GetHost()},
		}, nil
	case legacy.Inbound_Tun_case:
		tun := old.GetTun()
		return contract.Protocol{
			Type: contract.ProtocolTun,
			Tun: &contract.TunProtocol{
				Name:          tun.GetName(),
				MTU:           tun.GetMtu(),
				ForceFakeIP:   tun.GetForceFakeip(),
				SkipMulticast: tun.GetSkipMulticast(),
				Driver:        tun.GetDriver().String(),
				Portal:        tun.GetPortal(),
				PortalV6:      tun.GetPortalV6(),
				Routes:        append([]string(nil), tun.GetRoute().GetRoutes()...),
				Excludes:      append([]string(nil), tun.GetRoute().GetExcludes()...),
				PostUp:        append([]string(nil), tun.GetPostUp()...),
				PostDown:      append([]string(nil), tun.GetPostDown()...),
			},
		}, nil
	case legacy.Inbound_ReverseHttp_case:
		reverseHTTP := old.GetReverseHttp()
		return contract.Protocol{
			Type: contract.ProtocolReverseHTTP,
			ReverseHTTP: &contract.ReverseHTTPProtocol{
				URL: reverseHTTP.GetUrl(),
				TLS: convertLegacyClientTLS(reverseHTTP.GetTls()),
			},
		}, nil
	case legacy.Inbound_ReverseTcp_case:
		reverseTCP := old.GetReverseTcp()
		return contract.Protocol{
			Type:       contract.ProtocolReverseTCP,
			ReverseTCP: &contract.ReverseTCPProtocol{Target: reverseTCP.GetHost()},
		}, nil
	case legacy.Inbound_None_case:
		return contract.Protocol{Type: contract.ProtocolNone, None: &contract.NoneProtocol{}}, nil
	default:
		return contract.Protocol{}, fmt.Errorf("legacy inbound protocol is empty")
	}
}

func convertLegacyTransport(old *legacy.Transport) (contract.Transport, error) {
	switch old.WhichTransport() {
	case legacy.Transport_Normal_case:
		return contract.Transport{Type: contract.TransportNormal, Normal: &contract.NormalTransport{}}, nil
	case legacy.Transport_Tls_case:
		return contract.Transport{
			Type: contract.TransportTLS,
			TLS:  &contract.TLSTransport{TLS: convertLegacyServerTLS(old.GetTls().GetTls())},
		}, nil
	case legacy.Transport_Mux_case:
		return contract.Transport{Type: contract.TransportMux, Mux: &contract.MuxTransport{}}, nil
	case legacy.Transport_Http2_case:
		return contract.Transport{Type: contract.TransportHTTP2, HTTP2: &contract.HTTP2Transport{}}, nil
	case legacy.Transport_Websocket_case:
		return contract.Transport{Type: contract.TransportWebSocket, WebSocket: &contract.WebSocketTransport{}}, nil
	case legacy.Transport_Reality_case:
		reality := old.GetReality()
		return contract.Transport{
			Type: contract.TransportReality,
			Reality: &contract.RealityTransport{
				ShortIDs:    append([]string(nil), reality.GetShortId()...),
				ServerNames: append([]string(nil), reality.GetServerName()...),
				Dest:        reality.GetDest(),
				PrivateKey:  reality.GetPrivateKey(),
				PublicKey:   reality.GetPublicKey(),
				MLDSA65Seed: reality.GetMldsa65Seed(),
				Debug:       reality.GetDebug(),
			},
		}, nil
	case legacy.Transport_TlsAuto_case:
		tlsAuto := old.GetTlsAuto()
		return contract.Transport{
			Type: contract.TransportTLSAuto,
			TLSAuto: &contract.TLSAutoTransport{
				ServerNames:  append([]string(nil), tlsAuto.GetServernames()...),
				NextProtos:   append([]string(nil), tlsAuto.GetNextProtos()...),
				CACertBase64: append([]byte(nil), tlsAuto.GetCaCert()...),
				CAKeyBase64:  append([]byte(nil), tlsAuto.GetCaKey()...),
				ECH:          convertLegacyECH(tlsAuto.GetEch()),
			},
		}, nil
	case legacy.Transport_HttpMock_case:
		httpMock := old.GetHttpMock()
		return contract.Transport{
			Type:     contract.TransportHTTPMock,
			HTTPMock: &contract.HTTPMockTransport{DataBase64: append([]byte(nil), httpMock.GetData()...)},
		}, nil
	case legacy.Transport_Aead_case:
		aead := old.GetAead()
		return contract.Transport{
			Type: contract.TransportAEAD,
			AEAD: &contract.AEADTransport{
				Password:     aead.GetPassword(),
				CryptoMethod: aead.GetCryptoMethod().String(),
			},
		}, nil
	case legacy.Transport_Proxy_case:
		return contract.Transport{Type: contract.TransportProxy, Proxy: &contract.ProxyTransport{}}, nil
	default:
		return contract.Transport{}, fmt.Errorf("legacy transport is empty")
	}
}

func convertLegacyClientTLS(tls *legacynode.TlsConfig) *contract.ClientTLSConfig {
	if tls == nil {
		return nil
	}
	return &contract.ClientTLSConfig{
		Enabled:            tls.GetEnable(),
		ServerNames:        append([]string(nil), tls.GetServerNames()...),
		CACertsBase64:      cloneBytes2D(tls.GetCaCert()),
		InsecureSkipVerify: tls.GetInsecureSkipVerify(),
		NextProtos:         append([]string(nil), tls.GetNextProtos()...),
		ECHConfigBase64:    append([]byte(nil), tls.GetEchConfig()...),
	}
}

func convertLegacyServerTLS(tls *legacynode.TlsServerConfig) *contract.ServerTLSConfig {
	if tls == nil {
		return nil
	}
	out := &contract.ServerTLSConfig{
		Certificates:          make([]contract.Certificate, 0, len(tls.GetCertificates())),
		NextProtos:            append([]string(nil), tls.GetNextProtos()...),
		ServerNameCertificate: make(map[string]contract.Certificate, len(tls.GetServerNameCertificate())),
	}
	for _, certificate := range tls.GetCertificates() {
		out.Certificates = append(out.Certificates, convertLegacyCertificate(certificate))
	}
	for name, certificate := range tls.GetServerNameCertificate() {
		out.ServerNameCertificate[name] = convertLegacyCertificate(certificate)
	}
	if len(out.ServerNameCertificate) == 0 {
		out.ServerNameCertificate = nil
	}
	return out
}

func convertLegacyCertificate(certificate *legacynode.Certificate) contract.Certificate {
	if certificate == nil {
		return contract.Certificate{}
	}
	return contract.Certificate{
		CertBase64: append([]byte(nil), certificate.GetCert()...),
		KeyBase64:  append([]byte(nil), certificate.GetKey()...),
		CertFile:   certificate.GetCertFilePath(),
		KeyFile:    certificate.GetKeyFilePath(),
	}
}

func convertLegacyECH(ech *legacy.EchConfig) *contract.ECHConfig {
	if ech == nil {
		return nil
	}
	return &contract.ECHConfig{
		Enabled:          ech.GetEnable(),
		ConfigBase64:     append([]byte(nil), ech.GetConfig()...),
		PrivateKeyBase64: append([]byte(nil), ech.GetPrivateKey()...),
		OuterSNI:         ech.GetOuterSNI(),
	}
}

func cloneBytes2D(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		out = append(out, append([]byte(nil), value...))
	}
	return out
}
