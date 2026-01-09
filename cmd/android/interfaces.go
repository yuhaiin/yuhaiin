package yuhaiin

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	di "github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netmon"
)

var interfaces Interfaces

func SetInterfaces(i Interfaces) {
	interfaces = i
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) { return getInterfaces(i) })
	di.AltNetInterfaces = func() ([]di.Interface, error) {
		addr, err := getInterfaces(i)
		if err != nil {
			return nil, err
		}

		var ifaces = make([]di.Interface, 0, len(addr))
		for _, i := range addr {
			ifaces = append(ifaces, di.Interface{
				Interface: i.Interface,
				AltAddrs:  i.AltAddrs,
			})
		}

		return ifaces, nil
	}
}

type Interface struct {
	Address           AddressIter
	Name              string
	DisplayName       string
	HardwareAddr      []byte
	Index             int32
	Mtu               int32
	IsUp              bool
	IsLoopback        bool
	IsPointToPoint    bool
	Broadcast         bool
	SupportsMulticast bool
	IsVirtual         bool
}

type InterfaceIter interface {
	Next() *Interface
	HasNext() bool
	Reset()
}

type AddressPrefix struct {
	Address   string
	Broadcast string
	Mask      int32
}

type AddressIter interface {
	Next() *AddressPrefix
	HasNext() bool
	Reset()
}

type Interfaces interface {
	GetInterfaces() (InterfaceIter, error)
}

/*
  override fun getInterfacesAsString(): String {
    val interfaces: ArrayList<NetworkInterface> =
        java.util.Collections.list(NetworkInterface.getNetworkInterfaces())

    val sb = StringBuilder()
    for (nif in interfaces) {
      try {
        sb.append(
            String.format(
                Locale.ROOT,
                "%s %d %d %b %b %b %b %b |",
                nif.name,
                nif.index,
                nif.mtu,
                nif.isUp,
                nif.supportsMulticast(),
                nif.isLoopback,
                nif.isPointToPoint,
                nif.supportsMulticast()))

        for (ia in nif.interfaceAddresses) {
          val parts = ia.toString().split("/", limit = 0)
          if (parts.size > 1) {
            sb.append(String.format(Locale.ROOT, "%s/%d ", parts[1], ia.networkPrefixLength))
          }
        }
      } catch (e: Exception) {
        continue
      }
      sb.append("\n")
    }

    return sb.toString()
  }
*/
// Report interfaces in the device in net.Interface format.
func getInterfaces(ifs Interfaces) ([]netmon.Interface, error) {
	if ifs == nil {
		return nil, fmt.Errorf("getInterfaces: nil interfaces")
	}

	var ifaces []netmon.Interface

	is, err := ifs.GetInterfaces()
	if err != nil {
		return ifaces, err
	}

	for is.HasNext() {
		iface := is.Next()
		if iface == nil {
			break
		}

		newIf := netmon.Interface{
			Interface: &net.Interface{
				Name:         iface.Name,
				Index:        int(iface.Index),
				MTU:          int(iface.Mtu),
				HardwareAddr: iface.HardwareAddr,
			},
			AltAddrs: []net.Addr{}, // non-nil to avoid Go using netlink
		}
		if iface.IsUp {
			newIf.Flags |= net.FlagUp
		}
		if iface.Broadcast {
			newIf.Flags |= net.FlagBroadcast
		}
		if iface.IsLoopback {
			newIf.Flags |= net.FlagLoopback
		}
		if iface.IsPointToPoint {
			newIf.Flags |= net.FlagPointToPoint
		}
		if iface.SupportsMulticast {
			newIf.Flags |= net.FlagMulticast
		}

		addr := iface.Address
		for addr.HasNext() {
			addr := iface.Address.Next()
			if addr == nil {
				break
			}

			ipAddr, err := netip.ParseAddr(addr.Address)
			if err != nil {
				log.Warn("parse addr failed", "err", err, "addr", addr.Address)
				continue
			}

			m := net.CIDRMask(int(addr.Mask), ipAddr.BitLen())
			addr16 := ipAddr.As16()

			ipnet := &net.IPNet{IP: net.IP(addr16[:]).Mask(m), Mask: m}
			newIf.AltAddrs = append(newIf.AltAddrs, ipnet)

			log.Debug("get new address",
				"iface", newIf.Name,
				"addr", ipAddr,
				"prefix", ipnet,
				"broadcast", addr.Broadcast,
			)
		}

		log.Debug("get new iface",
			"display name", iface.DisplayName,
			"v", newIf.Interface, "addr", newIf.AltAddrs,
			"iface", iface,
		)

		ifaces = append(ifaces, newIf)
	}

	return ifaces, nil
}

type TunAddress struct {
	IPv4        string
	IPv6        string
	IPv4Address string
	IPv4Portal  string
	IPv6Address string
	IPv6Portal  string
}

func GetTunAddress() (*TunAddress, error) {
	addrs, err := getInterfaces(interfaces)
	if err != nil {
		return nil, err
	}

	existAddr := set.NewSet[netip.Prefix]()

	for _, iface := range addrs {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Error("get interfaces addrs failed", "err", err)
			continue
		}

		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			if pfx, ok := netaddr.FromStdIPNet(ipnet); ok {
				existAddr.Push(pfx)
			}
		}
	}

	ipv4, v4ok := findAvailableAddr(false, existAddr, 65535)
	ipv6, v6ok := findAvailableAddr(true, existAddr, 65535)
	if !v4ok || !v6ok {
		return nil, fmt.Errorf("no available address, v4: %v,%v, v6: %v,%v", ipv4, v4ok, ipv6, v6ok)
	}

	log.Info("get interfaces addrs", "ipv4", ipv4, "ipv6", ipv6, "addrs", existAddr)

	return &TunAddress{
		IPv4: ipv4.String(),
		IPv6: ipv6.String(),

		IPv4Address: ipv4.Next().String(),
		IPv6Address: ipv6.Next().String(),

		IPv4Portal: ipv4.Next().Next().String(),
		IPv6Portal: ipv6.Next().Next().String(),
	}, nil
}

func findAvailableAddr(v6 bool, existAddr *set.Set[netip.Prefix], maxTries int) (netip.Addr, bool) {
	for range maxTries {
		var addr netip.Prefix
		if v6 {
			addr = config.TunV6UlaGenerate().Masked()
		} else {
			addr = config.TunV4UlaGenerate().Masked()
		}
		if !existAddr.Has(addr) {
			return addr.Addr(), true
		}
	}
	return netip.Addr{}, false
}
