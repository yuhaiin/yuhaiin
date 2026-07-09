package migrate

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type LegacyPoint = legacy.Point

var errEmptyLegacyProtocol = errors.New("legacy protocol has no concrete object")

func ConvertLegacyNode(old *LegacyPoint) (contractnode.Node, []Warning, error) {
	if old == nil {
		return contractnode.Node{}, nil, errors.New("legacy node is nil")
	}
	out := contractnode.Node{
		ID:      old.GetHash(),
		Name:    old.GetName(),
		Group:   old.GetGroup(),
		Origin:  legacyOriginToContract(old.GetOrigin()),
		Enabled: true,
		Chain:   make([]contractnode.Protocol, 0, len(old.GetProtocols())),
	}
	var warnings []Warning
	for i, protocol := range old.GetProtocols() {
		converted, err := convertLegacyNodeProtocol(protocol)
		if err != nil {
			if errors.Is(err, errEmptyLegacyProtocol) {
				warnings = append(warnings, Warning{
					Entity:  "node " + old.GetHash(),
					Message: fmt.Sprintf("empty legacy chain entry at index %d skipped", i),
				})
				continue
			}
			return contractnode.Node{}, warnings, fmt.Errorf("convert node %q chain[%d] failed: %w", old.GetHash(), i, err)
		}
		out.Chain = append(out.Chain, converted)
	}
	if len(out.Chain) == 0 {
		direct, err := contractnode.NewProtocol("direct", nil)
		if err != nil {
			return contractnode.Node{}, warnings, err
		}
		out.Chain = append(out.Chain, direct)
		warnings = append(warnings, Warning{Entity: "node " + old.GetHash(), Message: "empty legacy chain replaced with direct"})
	}
	if err := out.Validate(); err != nil {
		return contractnode.Node{}, warnings, err
	}
	return out, warnings, nil
}

func ConvertContractNode(in contractnode.Node) (*legacy.Point, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	point := &legacy.Point{}
	point.SetHash(in.ID)
	point.SetName(in.Name)
	point.SetGroup(in.Group)
	point.SetOrigin(contractOriginToLegacy(in.Origin))
	point.SetProtocols(make([]*legacy.Protocol, 0, len(in.Chain)))
	for i, protocol := range in.Chain {
		converted, err := convertContractNodeProtocol(protocol)
		if err != nil {
			return nil, fmt.Errorf("convert node %q chain[%d] failed: %w", in.ID, i, err)
		}
		point.SetProtocols(append(point.GetProtocols(), converted))
	}
	return point, nil
}

func SyncLegacyNodeContract(ctx context.Context, execer plainstore.NodeExecer, point *legacy.Point, updatedAt int64) error {
	node, warnings, err := ConvertLegacyNode(point)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		fmt.Printf("plain node sync warning: %s: %s\n", warning.Entity, warning.Message)
	}
	return plainstore.SaveNodeContract(ctx, execer, node, updatedAt)
}

func DeleteLegacyNodeContract(ctx context.Context, execer plainstore.NodeExecer, id string) error {
	return plainstore.DeleteNodeContract(ctx, execer, id)
}

func convertLegacyNodeProtocol(old *legacy.Protocol) (contractnode.Protocol, error) {
	if old == nil {
		return contractnode.Protocol{}, errEmptyLegacyProtocol
	}
	switch {
	case old.GetShadowsocks() != nil:
		return legacyProtocolObject("shadowsocks", old.GetShadowsocks())
	case old.GetShadowsocksr() != nil:
		return legacyProtocolObject("shadowsocksr", old.GetShadowsocksr())
	case old.GetVmess() != nil:
		return legacyProtocolObject("vmess", old.GetVmess())
	case old.GetWebsocket() != nil:
		return legacyProtocolObject("websocket", old.GetWebsocket())
	case old.GetQuic() != nil:
		return legacyProtocolObject("quic", old.GetQuic())
	case old.GetObfsHttp() != nil:
		return legacyProtocolObject("obfs_http", old.GetObfsHttp())
	case old.GetTrojan() != nil:
		return legacyProtocolObject("trojan", old.GetTrojan())
	case old.GetSimple() != nil:
		return legacyProtocolObject("simple", old.GetSimple())
	case old.GetNone() != nil:
		return legacyProtocolObject("none", old.GetNone())
	case old.GetSocks5() != nil:
		return legacyProtocolObject("socks5", old.GetSocks5())
	case old.GetHttp() != nil:
		return legacyProtocolObject("http", old.GetHttp())
	case old.GetDirect() != nil:
		return legacyProtocolObject("direct", old.GetDirect())
	case old.GetReject() != nil:
		return legacyProtocolObject("reject", old.GetReject())
	case old.GetYuubinsya() != nil:
		return legacyProtocolObject("yuubinsya", old.GetYuubinsya())
	case old.GetHttp2() != nil:
		return legacyProtocolObject("http2", old.GetHttp2())
	case old.GetReality() != nil:
		return legacyProtocolObject("reality", old.GetReality())
	case old.GetTls() != nil:
		return legacyProtocolObject("tls", old.GetTls())
	case old.GetWireguard() != nil:
		return legacyProtocolObject("wireguard", old.GetWireguard())
	case old.GetMux() != nil:
		return legacyProtocolObject("mux", old.GetMux())
	case old.GetDrop() != nil:
		return legacyProtocolObject("drop", old.GetDrop())
	case old.GetVless() != nil:
		return legacyProtocolObject("vless", old.GetVless())
	case old.GetBootstrapDnsWarp() != nil:
		return legacyProtocolObject("bootstrap_dns_warp", old.GetBootstrapDnsWarp())
	case old.GetTailscale() != nil:
		return legacyProtocolObject("tailscale", old.GetTailscale())
	case old.GetSet() != nil:
		return legacyProtocolObject("set", old.GetSet())
	case old.GetTlsTermination() != nil:
		return legacyProtocolObject("tls_termination", old.GetTlsTermination())
	case old.GetHttpTermination() != nil:
		return legacyProtocolObject("http_termination", old.GetHttpTermination())
	case old.GetHttpMock() != nil:
		return legacyProtocolObject("http_mock", old.GetHttpMock())
	case old.GetAead() != nil:
		return legacyProtocolObject("aead", old.GetAead())
	case old.GetFixed() != nil:
		return legacyProtocolObject("fixed", old.GetFixed())
	case old.GetNetworkSplit() != nil:
		return convertLegacyNetworkSplit(old.GetNetworkSplit())
	case old.GetCloudflareWarpMasque() != nil:
		return legacyProtocolObject("cloudflare_warp_masque", old.GetCloudflareWarpMasque())
	case old.GetProxy() != nil:
		return legacyProtocolObject("proxy", old.GetProxy())
	case old.GetFixedv2() != nil:
		return legacyProtocolObject("fixedv2", old.GetFixedv2())
	case old.GetPointAsEndpoint() != nil:
		return legacyProtocolObject("point_as_endpoint", old.GetPointAsEndpoint())
	default:
		return contractnode.Protocol{}, errEmptyLegacyProtocol
	}
}

func convertLegacyNetworkSplit(old *legacy.NetworkSplit) (contractnode.Protocol, error) {
	if old == nil {
		return contractnode.Protocol{}, errors.New("legacy network split is nil")
	}
	tcp, err := convertLegacyNodeProtocol(old.GetTcp())
	if err != nil {
		return contractnode.Protocol{}, fmt.Errorf("convert network split tcp failed: %w", err)
	}
	udp, err := convertLegacyNodeProtocol(old.GetUdp())
	if err != nil {
		return contractnode.Protocol{}, fmt.Errorf("convert network split udp failed: %w", err)
	}
	return contractnode.NewProtocol("network_split", contractnode.NetworkSplit{
		TCP: &tcp,
		UDP: &udp,
	})
}

func convertContractNodeProtocol(in contractnode.Protocol) (*legacy.Protocol, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	out := &legacy.Protocol{}
	switch in.Type {
	case "shadowsocks":
		return setLegacyProtocolObject(out, in.Shadowsocks, out.SetShadowsocks)
	case "shadowsocksr":
		return setLegacyProtocolObject(out, in.Shadowsocksr, out.SetShadowsocksr)
	case "vmess":
		return setLegacyProtocolObject(out, in.Vmess, out.SetVmess)
	case "websocket":
		return setLegacyProtocolObject(out, in.Websocket, out.SetWebsocket)
	case "quic":
		return setLegacyProtocolObject(out, in.Quic, out.SetQuic)
	case "obfs_http":
		return setLegacyProtocolObject(out, in.ObfsHTTP, out.SetObfsHttp)
	case "trojan":
		return setLegacyProtocolObject(out, in.Trojan, out.SetTrojan)
	case "simple":
		return setLegacyProtocolObject(out, in.Simple, out.SetSimple)
	case "none":
		return setLegacyProtocolObject(out, in.None, out.SetNone)
	case "socks5":
		return setLegacyProtocolObject(out, in.Socks5, out.SetSocks5)
	case "http":
		return setLegacyProtocolObject(out, in.HTTP, out.SetHttp)
	case "direct":
		return setLegacyProtocolObject(out, in.Direct, out.SetDirect)
	case "reject":
		return setLegacyProtocolObject(out, in.Reject, out.SetReject)
	case "yuubinsya":
		return setLegacyProtocolObject(out, in.Yuubinsya, out.SetYuubinsya)
	case "http2":
		return setLegacyProtocolObject(out, in.HTTP2, out.SetHttp2)
	case "reality":
		return setLegacyProtocolObject(out, in.Reality, out.SetReality)
	case "tls":
		return setLegacyProtocolObject(out, in.TLS, out.SetTls)
	case "wireguard":
		return setLegacyProtocolObject(out, in.Wireguard, out.SetWireguard)
	case "mux":
		return setLegacyProtocolObject(out, in.Mux, out.SetMux)
	case "drop":
		return setLegacyProtocolObject(out, in.Drop, out.SetDrop)
	case "vless":
		return setLegacyProtocolObject(out, in.Vless, out.SetVless)
	case "bootstrap_dns_warp":
		return setLegacyProtocolObject(out, in.BootstrapDNSWarp, out.SetBootstrapDnsWarp)
	case "tailscale":
		return setLegacyProtocolObject(out, in.Tailscale, out.SetTailscale)
	case "set":
		return setLegacyProtocolObject(out, in.Set, out.SetSet)
	case "tls_termination":
		return setLegacyProtocolObject(out, in.TLSTermination, out.SetTlsTermination)
	case "http_termination":
		return setLegacyProtocolObject(out, in.HTTPTermination, out.SetHttpTermination)
	case "http_mock":
		return setLegacyProtocolObject(out, in.HTTPMock, out.SetHttpMock)
	case "aead":
		return setLegacyProtocolObject(out, in.AEAD, out.SetAead)
	case "fixed":
		return setLegacyProtocolObject(out, in.Fixed, out.SetFixed)
	case "network_split":
		return setLegacyProtocolObject(out, in.NetworkSplit, out.SetNetworkSplit)
	case "cloudflare_warp_masque":
		return setLegacyProtocolObject(out, in.CloudflareWarpMasque, out.SetCloudflareWarpMasque)
	case "proxy":
		return setLegacyProtocolObject(out, in.Proxy, out.SetProxy)
	case "fixedv2":
		return setLegacyProtocolObject(out, in.FixedV2, out.SetFixedv2)
	case "point_as_endpoint":
		return setLegacyProtocolObject(out, in.PointAsEndpoint, out.SetPointAsEndpoint)
	default:
		return nil, fmt.Errorf("unknown protocol type %q", in.Type)
	}
}

func legacyProtocolObject(typ string, value any) (contractnode.Protocol, error) {
	return contractnode.NewProtocol(typ, value)
}

func setLegacyProtocolObject[T any](out *legacy.Protocol, obj any, set func(*T)) (*legacy.Protocol, error) {
	if obj == nil {
		return nil, errors.New("missing concrete protocol object")
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal contract object failed: %w", err)
	}
	var target T
	if err := json.Unmarshal(data, &target); err != nil {
		return nil, fmt.Errorf("decode contract object failed: %w", err)
	}
	set(&target)
	return out, nil
}

func legacyOriginToContract(origin legacy.Origin) string {
	switch origin {
	case legacy.Origin_remote:
		return "remote"
	case legacy.Origin_manual:
		return "manual"
	default:
		return "reserve"
	}
}

func contractOriginToLegacy(origin string) legacy.Origin {
	switch origin {
	case "remote":
		return legacy.Origin_remote
	case "manual":
		return legacy.Origin_manual
	default:
		return legacy.Origin_reserve
	}
}
