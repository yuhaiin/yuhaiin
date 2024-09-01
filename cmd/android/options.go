package yuhaiin

import (
	"fmt"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type Opts struct {
	CloseFallback Closer
	MapStore      *MapStore
	TUN           *TUN   `json:"tun"`
	Savepath      string `json:"savepath"`
}

type TUN struct {
	UidDumper     UidDumper
	SocketProtect SocketProtect
	Portal        string `json:"portal"`
	PortalV6      string `json:"portal_v6"`
	FD            int32  `json:"fd"`
	MTU           int32  `json:"mtu"`
}

type UidDumper interface {
	DumpUid(ipProto int32, srcIp string, srcPort int32, destIp string, destPort int32) (int32, error)
	GetUidInfo(uid int32) (string, error)
}

type SocketProtect interface {
	Protect(socket int32) bool
}

type Closer interface {
	Close() error
}

type uidDumper struct {
	UidDumper
	cache syncmap.SyncMap[int32, string]
}

func NewUidDumper(ud UidDumper) netapi.ProcessDumper {
	if ud == nil {
		return nil
	}
	return &uidDumper{UidDumper: ud}
}

func (u *uidDumper) GetUidInfo(uid int32) (string, error) {
	if r, ok := u.cache.Load(uid); ok {
		return r, nil
	}

	r, err := u.UidDumper.GetUidInfo(uid)
	if err != nil {
		return "", err
	}

	u.cache.Store(uid, r)
	return r, nil
}

func (a *uidDumper) ProcessName(networks string, src, dst netapi.Address) (string, error) {
	var network int32
	switch networks {
	case "tcp":
		network = syscall.IPPROTO_TCP
	case "udp":
		network = syscall.IPPROTO_UDP
	}

	uid, err := a.UidDumper.DumpUid(network, src.Hostname(), int32(src.Port()), dst.Hostname(), int32(dst.Port()))
	if err != nil {
		log.Error("dump uid error", "err", err)
	}

	var name string
	if uid != 0 {
		name, err = a.UidDumper.GetUidInfo(uid)
		if err != nil {
			return "", fmt.Errorf("get uid info error: %v", err)
		}
	}

	return fmt.Sprintf("%s(%d)", name, uid), nil
}
