package nat

import (
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type addrStore struct {
	udp       syncmap.SyncMap[string, *net.UDPAddr]
	origin    syncmap.SyncMap[string, netapi.Address]
	distpatch syncmap.SyncMap[string, netapi.Address]
}

func (s *addrStore) StoreUdp(key string, addr *net.UDPAddr)         { s.udp.Store(key, addr) }
func (s *addrStore) StoreOrigin(key string, addr netapi.Address)    { s.origin.Store(key, addr) }
func (s *addrStore) StoreDispatch(key string, addr netapi.Address)  { s.distpatch.Store(key, addr) }
func (s *addrStore) LoadUdp(key string) (*net.UDPAddr, bool)        { return s.udp.Load(key) }
func (s *addrStore) LoadOrigin(key string) (netapi.Address, bool)   { return s.origin.Load(key) }
func (s *addrStore) LoadDispatch(key string) (netapi.Address, bool) { return s.distpatch.Load(key) }
