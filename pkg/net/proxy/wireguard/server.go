package wireguard

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
)

// ServerPeer is a client identity. AllowedIPs are deliberately limited to
// individual host addresses, preventing one peer from impersonating another.
type ServerPeer struct {
	PublicKey    string
	PreSharedKey string
	AllowedIPs   []string
}

type ServerConfig struct {
	PrivateKey string
	ListenPort int
	Addresses  []string
	MTU        int
	Peers      []ServerPeer
}

type inboundServer struct {
	device *device.Device
	tunnel *LightweightNetTun
	flows  netapi.Accepter
	once   sync.Once
	err    error
}

var _ netapi.Accepter = (*inboundServer)(nil)

func (s *inboundServer) Interface() string { return "wireguard" }

func (s *inboundServer) Close() error {
	s.once.Do(func() {
		s.device.Close()
		s.err = errors.Join(s.flows.Close(), s.tunnel.Close())
	})
	return s.err
}

func keyHex(value string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", errors.New("wireguard: expected 32-byte base64 key")
	}
	return hex.EncodeToString(key), nil
}

// serverIPC validates configuration before any sockets, goroutines or keys are
// installed. The standard wireguard-go bind owns its UDP socket.
func serverIPC(c ServerConfig) (*bytes.Buffer, []netip.Prefix, error) {
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return nil, nil, errors.New("wireguard: listenPort must be 1..65535")
	}
	secret, err := keyHex(c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("wireguard: privateKey: %w", err)
	}
	if len(c.Addresses) == 0 || len(c.Peers) == 0 {
		return nil, nil, errors.New("wireguard: addresses and peers are required")
	}
	addresses := make([]netip.Prefix, 0, len(c.Addresses))
	for _, entry := range c.Addresses {
		p, err := netip.ParsePrefix(entry)
		if err != nil || !p.IsValid() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return nil, nil, fmt.Errorf("wireguard: invalid server address %q", entry)
		}
		addresses = append(addresses, p)
	}
	if c.MTU == 0 {
		c.MTU = 1420
	}
	seenKeys := make(map[string]bool, len(c.Peers))
	seenIPs := make(map[netip.Prefix]bool)
	ipc := new(bytes.Buffer)
	fmt.Fprintf(ipc, "private_key=%s\nlisten_port=%d\n", secret, c.ListenPort)
	for i, peer := range c.Peers {
		public, err := keyHex(peer.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("wireguard: peer %d publicKey: %w", i, err)
		}
		if seenKeys[public] {
			return nil, nil, fmt.Errorf("wireguard: duplicate peer %d", i)
		}
		seenKeys[public] = true
		if len(peer.AllowedIPs) == 0 {
			return nil, nil, fmt.Errorf("wireguard: peer %d requires allowedIps", i)
		}
		fmt.Fprintf(ipc, "public_key=%s\nreplace_allowed_ips=true\n", public)
		if peer.PreSharedKey != "" {
			psk, err := keyHex(peer.PreSharedKey)
			if err != nil {
				return nil, nil, fmt.Errorf("wireguard: peer %d preSharedKey: %w", i, err)
			}
			fmt.Fprintf(ipc, "preshared_key=%s\n", psk)
		}
		for _, entry := range peer.AllowedIPs {
			p, err := netip.ParsePrefix(entry)
			if err != nil || !p.IsValid() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() ||
				p.Bits() != p.Addr().BitLen() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
				return nil, nil, fmt.Errorf("wireguard: peer %d invalid host allowedIp %q", i, entry)
			}
			if seenIPs[p] {
				return nil, nil, fmt.Errorf("wireguard: repeated client IP %s", p)
			}
			within := false
			for _, address := range addresses {
				if p.Addr() == address.Addr() {
					return nil, nil, fmt.Errorf("wireguard: client IP %s is the server address", p)
				}
				within = within || address.Contains(p.Addr())
			}
			if !within {
				return nil, nil, fmt.Errorf("wireguard: peer %d IP %s is outside server subnets", i, p)
			}
			seenIPs[p] = true
			fmt.Fprintf(ipc, "allowed_ip=%s\n", p)
		}
	}
	if strings.Contains(ipc.String(), "\r") {
		return nil, nil, errors.New("wireguard: invalid IPC")
	}
	return ipc, addresses, nil
}

// NewServer serves standard WireGuard peers through a memory-only IP stack and
// the same stream/datagram handlers used by the normal lightweight TUN inbound.
func NewServer(config ServerConfig, handler netapi.Handler) (netapi.Accepter, error) {
	return newServer(config, handler, nil)
}

func newServer(config ServerConfig, handler netapi.Handler, logger *device.Logger) (netapi.Accepter, error) {
	if handler == nil {
		return nil, errors.New("wireguard: nil inbound handler")
	}
	ipc, addresses, err := serverIPC(config)
	if err != nil {
		return nil, err
	}
	mtu := config.MTU
	if mtu == 0 {
		mtu = 1420
	}
	tunnel, err := CreateLightweightInboundTUN(addresses, mtu)
	if err != nil {
		return nil, err
	}
	flows, err := lightweighttun.NewFromStack(tunnel.Stack(), handler, addresses, "wireguard")
	if err != nil {
		_ = tunnel.Close()
		return nil, err
	}
	if logger == nil {
		logger = &device.Logger{
			Verbosef: func(string, ...any) {},
			Errorf: func(format string, args ...any) {
				log.Warn("wireguard inbound", "error", fmt.Sprintf(format, args...))
			},
		}
	}
	dev := device.NewDevice(tunnel, conn.NewDefaultBind(), logger)
	if err = dev.IpcSetOperation(ipc); err == nil {
		err = dev.Up()
	}
	if err != nil {
		dev.Close()
		_ = flows.Close()
		_ = tunnel.Close()
		return nil, fmt.Errorf("wireguard: start inbound: %w", err)
	}
	return &inboundServer{device: dev, tunnel: tunnel, flows: flows}, nil
}
