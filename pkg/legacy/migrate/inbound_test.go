package migrate

import (
	json "encoding/json/v2"
	"strings"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

func TestConvertLegacyInboundReverseHTTP(t *testing.T) {
	old := legacy.Inbound_builder{
		Name:    ptr("reversehttp"),
		Enabled: ptr(true),
		Tcpudp: legacy.Tcpudp_builder{
			Host:    ptr(":9002"),
			Control: legacy.TcpUdpControl_disable_udp.Enum(),
		}.Build(),
		ReverseHttp: legacy.ReverseHttp_builder{
			Url: ptr("http://127.0.0.1:3000"),
			Tls: legacynode.TlsConfig_builder{
				Enable:      ptr(true),
				ServerNames: []string{"example.com"},
				CaCert:      [][]byte{[]byte("ca")},
				NextProtos:  []string{"h2"},
			}.Build(),
		}.Build(),
		Transport: []*legacy.Transport{
			legacy.Transport_builder{Normal: legacy.Normal_builder{}.Build()}.Build(),
		},
	}.Build()

	got, warnings, err := ConvertLegacyInbound("reversehttp", old)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v", warnings)
	}
	if got.Network.Type != contract.NetworkTCPUDP || got.Network.TCPUDP.UDP != contract.UDPTCPOnly {
		t.Fatalf("network = %+v", got.Network)
	}
	if got.Protocol.Type != contract.ProtocolReverseHTTP || got.Protocol.ReverseHTTP.URL != "http://127.0.0.1:3000" {
		t.Fatalf("protocol = %+v", got.Protocol)
	}
	if got.Protocol.ReverseHTTP.TLS == nil || got.Protocol.ReverseHTTP.TLS.ServerNames[0] != "example.com" {
		t.Fatalf("reverse http tls = %+v", got.Protocol.ReverseHTTP.TLS)
	}

	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"config"`) {
		t.Fatalf("migrated json must not contain config wrapper: %s", data)
	}
	if !strings.Contains(string(data), `"reverse_http"`) {
		t.Fatalf("migrated json missing reverse_http field: %s", data)
	}
}

func TestConvertLegacyInboundTLSAutoTransport(t *testing.T) {
	old := legacy.Inbound_builder{
		Name:    ptr("mixed"),
		Enabled: ptr(true),
		Tcpudp: legacy.Tcpudp_builder{
			Host:    ptr(":1080"),
			Control: legacy.TcpUdpControl_tcp_udp_control_all.Enum(),
		}.Build(),
		Mix: legacy.Mixed_builder{}.Build(),
		Transport: []*legacy.Transport{
			legacy.Transport_builder{
				TlsAuto: legacy.TlsAuto_builder{
					Servernames: []string{"*.hicloud.com"},
					NextProtos:  []string{"h2", "http/1.1"},
					CaCert:      []byte("cert"),
					CaKey:       []byte("key"),
					Ech: legacy.EchConfig_builder{
						Enable:     ptr(true),
						Config:     []byte("ech-config"),
						PrivateKey: []byte("ech-key"),
						OuterSNI:   ptr("public.example.com"),
					}.Build(),
				}.Build(),
			}.Build(),
		},
	}.Build()

	got, _, err := ConvertLegacyInbound("mixed", old)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Transports) != 1 || got.Transports[0].Type != contract.TransportTLSAuto {
		t.Fatalf("transports = %+v", got.Transports)
	}
	tlsAuto := got.Transports[0].TLSAuto
	if tlsAuto == nil || tlsAuto.ServerNames[0] != "*.hicloud.com" || tlsAuto.ECH == nil || !tlsAuto.ECH.Enabled {
		t.Fatalf("tlsAuto = %+v", tlsAuto)
	}

	data, err := json.Marshal(got.Transports[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"tls_auto"`) {
		t.Fatalf("transport json missing tls_auto field: %s", data)
	}
}

func TestConvertLegacyInboundRejectsEnabledEmptyProtocol(t *testing.T) {
	old := legacy.Inbound_builder{
		Name:    ptr("broken"),
		Enabled: ptr(true),
		Empty:   legacy.Empty_builder{}.Build(),
	}.Build()

	if _, _, err := ConvertLegacyInbound("broken", old); err == nil {
		t.Fatal("ConvertLegacyInbound succeeded for enabled inbound without protocol")
	}
}

func TestConvertLegacyInboundDropsEmptyTransport(t *testing.T) {
	old := legacy.Inbound_builder{
		Name:    ptr("mixed"),
		Enabled: ptr(true),
		Empty:   legacy.Empty_builder{}.Build(),
		Mix:     legacy.Mixed_builder{}.Build(),
		Transport: []*legacy.Transport{
			legacy.Transport_builder{}.Build(),
		},
	}.Build()

	got, warnings, err := ConvertLegacyInbound("mixed", old)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Transports) != 0 {
		t.Fatalf("transports = %+v", got.Transports)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "transport[0] is empty") {
		t.Fatalf("warnings = %+v", warnings)
	}
}

func ptr[T any](value T) *T {
	return &value
}
