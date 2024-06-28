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
	Bypass        *Bypass     `json:"bypass"`
	DNS           *DNSSetting `json:"dns"`
	TUN           *TUN        `json:"tun"`
	Log           *Log        `json:"log"`
	Host          string      `json:"host"`
	Savepath      string      `json:"savepath"`
	Socks5        string      `json:"socks5"`
	Http          string      `json:"http"`
	IPv6          bool        `json:"ipv6"`
}

type Log struct {
	SaveLogcat bool `json:"save_logcat"`
	// 0:verbose, 1:debug, 2:info, 3:warning, 4:error, 5: fatal
	LogLevel int32 `json:"log_level"`
}

type Bypass struct {
	Block  string `json:"block"`
	Proxy  string `json:"proxy"`
	Direct string `json:"direct"`
	// 0: bypass, 1: proxy, 2: direct, 3: block
	TCP int32 `json:"tcp"`
	// 0: bypass, 1: proxy, 2: direct, 3: block
	UDP                int32 `json:"udp"`
	Sniffy             bool  `json:"sniffy"`
	UDPSkipResolveFqdn bool  `json:"udp_skip_resolve_fqdn"`
}

type DNSSetting struct {
	Remote              *DNS   `json:"remote"`
	Local               *DNS   `json:"local"`
	Bootstrap           *DNS   `json:"bootstrap"`
	Server              string `json:"server"`
	FakednsIpRange      string `json:"fakedns_ip_range"`
	FakednsIpv6Range    string `json:"fakedns_ipv6_range"`
	Hosts               []byte `json:"hosts"`
	Fakedns             bool   `json:"fakedns"`
	ResolveRemoteDomain bool   `json:"resolve_remote_domain"`
}

type DNS struct {
	Host          string `json:"host"`
	Subnet        string `json:"subnet"`
	TlsServername string `json:"tls_servername"`
	// Type
	// 0: reserve
	// 1: udp
	// 2: tcp
	// 3: doh
	// 4: dot
	// 5: doq
	// 6: doh3
	Type int32 `json:"type"`
}

type TUN struct {
	UidDumper     UidDumper
	SocketProtect SocketProtect
	Portal        string `json:"portal"`
	PortalV6      string `json:"portal_v6"`
	FD            int32  `json:"fd"`
	MTU           int32  `json:"mtu"`
	// Driver
	// 0: fdbased
	// 1: channel
	// 2: tun2socket
	// 3: tun2socket_gvisor
	Driver       int32 `json:"driver"`
	DNSHijacking bool  `json:"dns_hijacking"`
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
