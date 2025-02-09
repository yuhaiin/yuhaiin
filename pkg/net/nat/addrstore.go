package nat

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type addrStore struct {
	udp       syncmap.SyncMap[netapi.ComparableAddress, *net.UDPAddr]
	origin    syncmap.SyncMap[netapi.ComparableAddress, netapi.Address]
	distpatch syncmap.SyncMap[netapi.ComparableAddress, netapi.Address]
}

func (s *addrStore) StoreUdp(key netapi.ComparableAddress, addr *net.UDPAddr) { s.udp.Store(key, addr) }
func (s *addrStore) StoreOrigin(key netapi.ComparableAddress, addr netapi.Address) {
	s.origin.Store(key, addr)
}
func (s *addrStore) StoreDispatch(key netapi.ComparableAddress, addr netapi.Address) {
	s.distpatch.Store(key, addr)
}
func (s *addrStore) LoadUdp(key netapi.ComparableAddress) (*net.UDPAddr, bool) {
	return s.udp.Load(key)
}
func (s *addrStore) LoadOrigin(key netapi.ComparableAddress) (netapi.Address, bool) {
	return s.origin.Load(key)
}
func (s *addrStore) LoadDispatch(key netapi.ComparableAddress) (netapi.Address, bool) {
	return s.distpatch.Load(key)
}
