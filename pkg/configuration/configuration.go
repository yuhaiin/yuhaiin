package configuration

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

var Lite = os.Getenv("YUHAIIN_LITE") == "true"

var (
	LogNaxSize            = or(1024*1024, 1024*256)
	LogMaxFile            = or(5, 0)
	IgnoreDnsErrorLog     atomic.Bool
	IgnoreTimeoutErrorLog atomic.Bool

	DNSCache = or[uint](1024, 256)

	ProcessDumper = or(true, false)

	Timeout         = time.Second * 20
	ResolverTimeout = time.Second * 5

	SnifferBufferSize = pool.DefaultSize

	UDPBatchSize             = 8
	MaxUDPUnprocessedPackets = atomicx.NewValue(250)
	UDPBufferSize            = atomicx.NewValue(2048)
	RelayBufferSize          = atomicx.NewValue(4096)
	DNSProcessThread         = atomicx.NewValue(4)

	MPTCP = true

	UDPChannelBufferSize = 2500

	IPv6 = atomicx.NewValue(true)
	// resolver fake ip or inbound fake ip enable
	FakeIPEnabled = atomicx.NewValue(false)

	HistorySize = or[uint](1000, 500)

	DataDir = atomicx.NewValue(DefaultConfigDir())

	ProxyChain = netapi.NewDynamicProxy(netapi.NewErrProxy(errors.New("not initialized")))
)

func DefaultConfigDir() (Path string) {
	var err error
	Path, err = os.UserConfigDir()
	if err == nil {
		Path = filepath.Join(Path, "yuhaiin")
		return
	}

	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		fmt.Println("lookpath failed", "err", err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}
	execPath, err := filepath.Abs(file)
	if err != nil {
		fmt.Println("get file abs failed", "err", err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}

	Path = filepath.Join(filepath.Dir(execPath), "config")
	return
}

func or[T any](a, b T) T {
	if Lite {
		return b
	}

	return a
}

func GetFakeIPRange(ipRange string, ipv6 bool) netip.Prefix {
	ipf, err := netip.ParsePrefix(ipRange)
	if err == nil {
		return ipf
	}

	if ipv6 {
		return netip.MustParsePrefix("fc00::/64")
	} else {
		return netip.MustParsePrefix("10.2.0.1/24")
	}
}
