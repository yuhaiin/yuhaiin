package legacyruntime

import (
	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	yhttp "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	yhttp2 "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/masque"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/mock"
	ymux "github.com/Asutorufa/yuhaiin/pkg/net/proxy/mux"
	yproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reverse"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vless"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterPoint(func(p *legacynode.Direct, _ netapi.Proxy) (netapi.Proxy, error) {
		if p.GetNetworkInterface() != "" {
			return direct.NewDirect(direct.WithInterface(p.GetNetworkInterface())), nil
		}
		return direct.Default, nil
	})
	register.RegisterPoint(func(*legacynode.Drop, netapi.Proxy) (netapi.Proxy, error) {
		return drop.Drop, nil
	})
	register.RegisterPoint(func(*legacynode.Reject, netapi.Proxy) (netapi.Proxy, error) {
		return reject.Default, nil
	})
	register.RegisterPoint(func(config *legacynode.Mux, proxy netapi.Proxy) (netapi.Proxy, error) {
		return ymux.NewClient(ymux.Config{Concurrency: config.GetConcurrency()}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Http2, proxy netapi.Proxy) (netapi.Proxy, error) {
		return yhttp2.NewClient(yhttp2.Config{Concurrency: config.GetConcurrency()}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Http, proxy netapi.Proxy) (netapi.Proxy, error) {
		return yhttp.NewClient(yhttp.Config{
			User:     config.GetUser(),
			Password: config.GetPassword(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Fixed, proxy netapi.Proxy) (netapi.Proxy, error) {
		return fixed.NewClient(fixed.Config{
			Host:             config.GetHost(),
			Port:             config.GetPort(),
			AlternateHost:    fixedAddressesFromLegacy(config.GetAlternateHost()),
			NetworkInterface: config.GetNetworkInterface(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Fixedv2, proxy netapi.Proxy) (netapi.Proxy, error) {
		return fixed.NewClientv2(fixed.ConfigV2{
			Addresses:        fixedV2AddressesFromLegacy(config.GetAddresses()),
			UDPHappyEyeballs: config.GetUdpHappyEyeballs(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Simple, proxy netapi.Proxy) (netapi.Proxy, error) {
		return fixed.NewClient(fixed.Config{
			Host:             config.GetHost(),
			Port:             config.GetPort(),
			AlternateHost:    fixedAddressesFromLegacy(config.GetAlternateHost()),
			NetworkInterface: config.GetNetworkInterface(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Socks5, proxy netapi.Proxy) (netapi.Proxy, error) {
		return socks5.NewClient(socks5.Config{
			User:         config.GetUser(),
			Password:     config.GetPassword(),
			Hostname:     config.GetHostname(),
			OverridePort: int32(config.GetOverridePort()),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Websocket, proxy netapi.Proxy) (netapi.Proxy, error) {
		return websocket.NewClient(websocket.Config{
			Host: config.GetHost(),
			Path: config.GetPath(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Yuubinsya, proxy netapi.Proxy) (netapi.Proxy, error) {
		return yuubinsya.NewClient(yuubinsya.Config{
			Password:      config.GetPassword(),
			UDPOverStream: config.GetUdpOverStream(),
			UDPCoalesce:   config.GetUdpCoalesce(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.HttpTermination, proxy netapi.Proxy) (netapi.Proxy, error) {
		return reverse.NewHttpTermination(reverse.Config{
			Headers: httpTerminationHeadersFromLegacy(config.GetHeaders()),
		}, proxy)
	})
	register.RegisterPoint(func(_ *legacynode.HttpMock, proxy netapi.Proxy) (netapi.Proxy, error) {
		return mock.NewClient(mock.Config{}, proxy)
	})
	register.RegisterPoint(func(_ *legacynode.Proxy, proxy netapi.Proxy) (netapi.Proxy, error) {
		return yproxy.NewClient(yproxy.Config{}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Shadowsocks, proxy netapi.Proxy) (netapi.Proxy, error) {
		return shadowsocks.NewClient(shadowsocks.Config{
			Method:   config.GetMethod(),
			Password: config.GetPassword(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.ObfsHttp, proxy netapi.Proxy) (netapi.Proxy, error) {
		return shadowsocks.NewHTTPOBFS(shadowsocks.HTTPObfsConfig{
			Host: config.GetHost(),
			Port: config.GetPort(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Shadowsocksr, proxy netapi.Proxy) (netapi.Proxy, error) {
		return shadowsocksr.NewClient(shadowsocksr.Config{
			Server:     config.GetServer(),
			Port:       config.GetPort(),
			Method:     config.GetMethod(),
			Password:   config.GetPassword(),
			Obfs:       config.GetObfs(),
			ObfsParam:  config.GetObfsparam(),
			Protocol:   config.GetProtocol(),
			ProtoParam: config.GetProtoparam(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Vmess, proxy netapi.Proxy) (netapi.Proxy, error) {
		return vmess.NewClient(vmess.Config{
			UUID:     config.GetUuid(),
			AlterID:  config.GetAlterId(),
			Security: config.GetSecurity(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Vless, proxy netapi.Proxy) (netapi.Proxy, error) {
		return vless.NewClient(vless.Config{UUID: config.GetUuid()}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Trojan, proxy netapi.Proxy) (netapi.Proxy, error) {
		return trojan.NewClient(trojan.Config{
			Password: config.GetPassword(),
			Peer:     config.GetPeer(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Aead, proxy netapi.Proxy) (netapi.Proxy, error) {
		return aead.NewClient(aead.Config{
			Password:     config.GetPassword(),
			CryptoMethod: aead.CryptoMethod(config.GetCryptoMethod().String()),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Reality, proxy netapi.Proxy) (netapi.Proxy, error) {
		return reality.NewClient(reality.Config{
			ServerName:    config.GetServerName(),
			PublicKey:     config.GetPublicKey(),
			MLDSA65Verify: config.GetMldsa65Verify(),
			ShortID:       config.GetShortId(),
			Debug:         config.GetDebug(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.CloudflareWarpMasque, proxy netapi.Proxy) (netapi.Proxy, error) {
		return masque.NewCloudflareWarpMasque(masque.Config{
			PrivateKey:        config.GetPrivateKey(),
			Endpoint:          config.GetEndpoint(),
			EndpointPublicKey: config.GetEndpointPublicKey(),
			LocalAddresses:    config.GetLocalAddresses(),
			MTU:               config.GetMtu(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.TlsConfig, proxy netapi.Proxy) (netapi.Proxy, error) {
		return ytls.NewClient(tlsConfigFromLegacy(config), proxy)
	})
	register.RegisterPoint(func(config *legacynode.Quic, proxy netapi.Proxy) (netapi.Proxy, error) {
		return quic.NewClient(quic.Config{
			Host: config.GetHost(),
			TLS:  tlsConfigFromLegacy(config.GetTls()),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Wireguard, proxy netapi.Proxy) (netapi.Proxy, error) {
		return wireguard.NewClient(wireguard.Config{
			SecretKey: config.GetSecretKey(),
			Endpoint:  config.GetEndpoint(),
			Peers:     wireguardPeersFromLegacy(config.GetPeers()),
			MTU:       config.GetMtu(),
			Reserved:  config.GetReserved(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.Tailscale, proxy netapi.Proxy) (netapi.Proxy, error) {
		return tailscale.New(tailscale.Config{
			AuthKey:    config.GetAuthKey(),
			Hostname:   config.GetHostname(),
			ControlURL: config.GetControlUrl(),
			Debug:      config.GetDebug(),
		}, proxy)
	})
	register.RegisterPoint(func(config *legacynode.TlsTermination, proxy netapi.Proxy) (netapi.Proxy, error) {
		tlsConfig, err := ytls.ParseServerTLSConfig(serverTLSConfigFromLegacy(config.GetTls()))
		if err != nil {
			return nil, err
		}
		return ytls.NewUnWrapTls(tlsConfig, proxy)
	})
}

func tlsConfigFromLegacy(config *legacynode.TlsConfig) ytls.TLSConfig {
	if config == nil {
		return ytls.TLSConfig{}
	}
	return ytls.TLSConfig{
		Enable:             config.GetEnable(),
		ServerNames:        config.GetServerNames(),
		CACert:             config.GetCaCert(),
		InsecureSkipVerify: config.GetInsecureSkipVerify(),
		NextProtos:         config.GetNextProtos(),
		ECHConfig:          config.GetEchConfig(),
	}
}

func serverTLSConfigFromLegacy(config *legacynode.TlsServerConfig) ytls.ServerConfig {
	if config == nil {
		return ytls.ServerConfig{}
	}
	out := ytls.ServerConfig{
		NextProtos:            config.GetNextProtos(),
		Certificates:          certificateConfigsFromLegacy(config.GetCertificates()),
		ServerNameCertificate: make(map[string]ytls.CertificateConfig, len(config.GetServerNameCertificate())),
	}
	for name, cert := range config.GetServerNameCertificate() {
		out.ServerNameCertificate[name] = certificateConfigFromLegacy(cert)
	}
	if len(out.ServerNameCertificate) == 0 {
		out.ServerNameCertificate = nil
	}
	return out
}

func certificateConfigsFromLegacy(in []*legacynode.Certificate) []ytls.CertificateConfig {
	out := make([]ytls.CertificateConfig, 0, len(in))
	for _, cert := range in {
		out = append(out, certificateConfigFromLegacy(cert))
	}
	return out
}

func certificateConfigFromLegacy(config *legacynode.Certificate) ytls.CertificateConfig {
	if config == nil {
		return ytls.CertificateConfig{}
	}
	return ytls.CertificateConfig{
		Cert:         config.GetCert(),
		Key:          config.GetKey(),
		CertFilePath: config.GetCertFilePath(),
		KeyFilePath:  config.GetKeyFilePath(),
	}
}

func wireguardPeersFromLegacy(in []*legacynode.WireguardPeerConfig) []wireguard.PeerConfig {
	out := make([]wireguard.PeerConfig, 0, len(in))
	for _, peer := range in {
		if peer == nil {
			continue
		}
		out = append(out, wireguard.PeerConfig{
			PublicKey:    peer.GetPublicKey(),
			PreSharedKey: peer.GetPreSharedKey(),
			Endpoint:     peer.GetEndpoint(),
			KeepAlive:    peer.GetKeepAlive(),
			AllowedIPs:   peer.GetAllowedIps(),
		})
	}
	return out
}

func fixedAddressesFromLegacy(in []*legacynode.Host) []fixed.ConfigAddress {
	out := make([]fixed.ConfigAddress, 0, len(in))
	for _, addr := range in {
		if addr == nil {
			continue
		}
		out = append(out, fixed.ConfigAddress{
			Host: addr.GetHost(),
			Port: addr.GetPort(),
		})
	}
	return out
}

func fixedV2AddressesFromLegacy(in []*legacynode.Fixedv2Address) []fixed.ConfigAddress {
	out := make([]fixed.ConfigAddress, 0, len(in))
	for _, addr := range in {
		if addr == nil {
			continue
		}
		out = append(out, fixed.ConfigAddress{
			Host:             addr.GetHost(),
			NetworkInterface: addr.GetNetworkInterface(),
		})
	}
	return out
}

func httpTerminationHeadersFromLegacy(in map[string]*legacynode.HttpTerminationHttpHeaders) map[string]reverse.HTTPHeaders {
	out := make(map[string]reverse.HTTPHeaders, len(in))
	for key, value := range in {
		if value == nil {
			continue
		}
		headers := make([]reverse.HTTPHeader, 0, len(value.GetHeaders()))
		for _, header := range value.GetHeaders() {
			if header == nil {
				continue
			}
			headers = append(headers, reverse.HTTPHeader{
				Key:   header.GetKey(),
				Value: header.GetValue(),
			})
		}
		out[key] = reverse.HTTPHeaders{Headers: headers}
	}
	return out
}
