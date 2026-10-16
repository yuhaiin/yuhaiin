package lightweight

import (
	"net/netip"
	"testing"
)

func TestDualStackBindExclusivity(t *testing.T) {
	for _, transport := range []string{"TCP", "UDP"} {
		for _, firstDual := range []bool{false, true} {
			for _, family := range []string{"0.0.0.0", "::"} {
				t.Run(transport+"/"+family+map[bool]string{false: "/family-first", true: "/dual-first"}[firstDual], func(t *testing.T) {
					s, _ := stackPair(t)
					familyAddr := netip.AddrPortFrom(netip.MustParseAddr(family), 9000)
					bind := func(dual bool) error {
						if transport == "TCP" {
							if dual {
								_, err := s.ListenDualTCP(9000)
								return err
							}
							_, err := s.ListenTCP(familyAddr)
							return err
						}
						if dual {
							_, err := s.ListenDualUDP(9000)
							return err
						}
						_, err := s.ListenUDP(familyAddr)
						return err
					}
					if err := bind(firstDual); err != nil {
						t.Fatal(err)
					}
					if err := bind(!firstDual); err == nil {
						t.Fatal("dual and single-family sockets shared a bound port")
					}
				})
			}
		}
	}
}

func TestTCPFamilyEphemeralListener(t *testing.T) {
	s, _ := stackPair(t)
	for _, family := range []string{"0.0.0.0", "::"} {
		a := netip.AddrPortFrom(netip.MustParseAddr(family), 0)
		first, err := s.ListenTCP(a)
		if err != nil {
			t.Fatal(err)
		}
		second, err := s.ListenTCP(a)
		if err != nil {
			t.Fatal(err)
		}
		if first.local.Port() == 0 || first.local == second.local {
			t.Fatal("ephemeral listeners did not get distinct ports")
		}
		if s.listener(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), first.local.Port())) == first && family == "::" {
			t.Fatal("single-family IPv6 listener accepted IPv4")
		}
	}
}
