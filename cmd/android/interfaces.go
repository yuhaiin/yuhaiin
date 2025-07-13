package yuhaiin

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netmon"
)

var interfaces Interfaces

func SetInterfaces(i Interfaces) {
	interfaces = i
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) { return getInterfaces(i) })
	tun2socket.AltNetInterfaces = func() ([]tun2socket.Interface, error) {
		addr, err := getInterfaces(i)
		if err != nil {
			return nil, err
		}

		var ifaces = make([]tun2socket.Interface, 0, len(addr))
		for _, i := range addr {
			ifaces = append(ifaces, tun2socket.Interface{
				Interface: i.Interface,
				AltAddrs:  i.AltAddrs,
			})
		}

		return ifaces, nil
	}
}

type Interfaces interface {
	GetInterfacesAsString() (string, error)
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

	ifaceString, err := ifs.GetInterfacesAsString()
	if err != nil {
		return ifaces, err
	}

	for iface := range strings.SplitSeq(ifaceString, "\n") {
		// Example of the strings we're processing:
		// wlan0 30 1500 true true false false true | fe80::2f60:2c82:4163:8389%wlan0/64 10.1.10.131/24
		// r_rmnet_data0 21 1500 true false false false false | fe80::9318:6093:d1ad:ba7f%r_rmnet_data0/64
		// mnet_data2 12 1500 true false false false false | fe80::3c8c:44dc:46a9:9907%rmnet_data2/64

		if strings.TrimSpace(iface) == "" {
			continue
		}

		fields := strings.Split(iface, "|")
		if len(fields) != 2 {
			log.Error("getInterfaces: unable to split", "iface", iface)
			continue
		}

		var name string
		var index, mtu int
		var up, broadcast, loopback, pointToPoint, multicast bool
		_, err := fmt.Sscanf(fields[0], "%s %d %d %t %t %t %t %t",
			&name, &index, &mtu, &up, &broadcast, &loopback, &pointToPoint, &multicast)
		if err != nil {
			log.Error("getInterfaces: unable to parse", "iface", iface, "err", err)
			continue
		}

		newIf := netmon.Interface{
			Interface: &net.Interface{
				Name:  name,
				Index: index,
				MTU:   mtu,
			},
			AltAddrs: []net.Addr{}, // non-nil to avoid Go using netlink
		}
		if up {
			newIf.Flags |= net.FlagUp
		}
		if broadcast {
			newIf.Flags |= net.FlagBroadcast
		}
		if loopback {
			newIf.Flags |= net.FlagLoopback
		}
		if pointToPoint {
			newIf.Flags |= net.FlagPointToPoint
		}
		if multicast {
			newIf.Flags |= net.FlagMulticast
		}

		addrs := strings.Trim(fields[1], " \n")
		for addr := range strings.SplitSeq(addrs, " ") {
			_, ip, err := net.ParseCIDR(addr)
			if err == nil {
				newIf.AltAddrs = append(newIf.AltAddrs, ip)
			}
		}

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

	var ipv4, ipv6 netip.Addr

	for i := range 255 {
		addr := netip.AddrFrom4([4]byte{172, 19, byte(i), 0})
		if !existAddr.Has(netip.PrefixFrom(addr, 24)) {
			ipv4 = addr
			break
		}
	}

	if !ipv4.IsValid() {
		return nil, fmt.Errorf("get interfaces v4 addr, all addr used")
	}

	for i := range 255 {
		addr := netip.AddrFrom16([16]byte{0xfd, 0xfe, 0xdc, 0xba, 0x98, byte(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		if !existAddr.Has(netip.PrefixFrom(addr, 64)) {
			ipv6 = addr
			break
		}
	}

	if !ipv6.IsValid() {
		return nil, fmt.Errorf("get interfaces v6 addr, all addr used")
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
