package nat

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type addrStore struct {
	udp      syncmap.SyncMap[uint64, *net.UDPAddr]
	origin   syncmap.SyncMap[uint64, netapi.Address]
	dispatch syncmap.SyncMap[uint64, netapi.Address]
}

func (s *addrStore) StoreUdp(key uint64, addr *net.UDPAddr) { s.udp.Store(key, addr) }
func (s *addrStore) StoreOrigin(key uint64, addr netapi.Address) {
	s.origin.Store(key, addr)
}
func (s *addrStore) StoreDispatch(key uint64, addr netapi.Address) {
	s.dispatch.Store(key, addr)
}
func (s *addrStore) LoadUdp(key uint64) (*net.UDPAddr, bool) {
	return s.udp.Load(key)
}
func (s *addrStore) LoadOrigin(key uint64) (netapi.Address, bool) {
	return s.origin.Load(key)
}
func (s *addrStore) LoadDispatch(key uint64) (netapi.Address, bool) {
	return s.dispatch.Load(key)
}
