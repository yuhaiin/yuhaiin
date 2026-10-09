package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	hyutils "github.com/apernet/hysteria/extras/v2/utils"
)

// QUIC sees one logical peer; the packet connection selects the actual relay.
type addressHopAddr struct {
	net.Addr
	targets []hopTarget
}

type hopTarget struct {
	ip    net.IP
	ports []uint16
}

func validateHopAddresses(config node.Hysteria2) error {
	for _, value := range append([]string{config.Host}, config.HopAddresses...) {
		addr, _, err := parseServerAddress(value)
		if err != nil {
			return fmt.Errorf("hysteria2 address %q: %w", value, err)
		}
		if addr.Hostname() == "" {
			return errors.New("hysteria2 hopping address has an empty host")
		}
		if len(config.HopAddresses) != 0 {
			if ip, ok := addr.(netapi.IPAddress); ok && ip.AddrPort().Addr().Zone() != "" {
				return errors.New("hysteria2 address hopping does not support scoped IPv6 addresses")
			}
		}
	}
	return nil
}

func resolveHopAddress(ctx context.Context, addr netapi.Address) (*net.UDPAddr, error) {
	port := addr.Port()
	if port == 0 {
		port = 443
	}
	if ip, ok := addr.(netapi.IPAddress); ok {
		remote := net.UDPAddrFromAddrPort(ip.AddrPort())
		remote.Port = int(port)
		return remote, nil
	}
	ips, err := netapi.ResolverIP(ctx, addr.Hostname())
	if err != nil {
		return nil, err
	}
	if ips.Len() == 0 {
		return nil, fmt.Errorf("hysteria2 address %q resolved to no IPs", addr.Hostname())
	}
	return ips.RandUDPAddr(port), nil
}

func resolveAddressHops(ctx context.Context, config node.Hysteria2, remote *net.UDPAddr, ports hyutils.PortUnion) (*addressHopAddr, error) {
	result := &addressHopAddr{Addr: remote}
	if err := result.add(remote, ports); err != nil {
		return nil, err
	}
	for _, value := range config.HopAddresses {
		addr, ports, err := parseServerAddress(value)
		if err != nil {
			return nil, err
		}
		remote, err := resolveHopAddress(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("hysteria2 resolve relay %q: %w", value, err)
		}
		if err := result.add(remote, ports); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (a *addressHopAddr) add(remote *net.UDPAddr, ports hyutils.PortUnion) error {
	if remote.Zone != "" {
		return errors.New("hysteria2 address hopping does not support scoped IPv6 addresses")
	}
	values := []uint16{uint16(remote.Port)}
	if ports != nil {
		values = ports.Ports()
	}
	// Group by resolved IP so a relay's port range doesn't give it more weight
	// than another relay. Merge duplicates to avoid hopping to the same IP.
	index := slices.IndexFunc(a.targets, func(target hopTarget) bool { return target.ip.Equal(remote.IP) })
	if index == -1 {
		a.targets = append(a.targets, hopTarget{ip: remote.IP})
		index = len(a.targets) - 1
	}
	values = append(values, a.targets[index].ports...)
	slices.Sort(values)
	a.targets[index].ports = slices.Compact(values)
	return nil
}
