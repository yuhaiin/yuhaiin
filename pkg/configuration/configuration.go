package configuration

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
)

var Lite = os.Getenv("YUHAIIN_LITE") == "true"

var (
	LogNaxSize            = or(1024*1024, 1024*256)
	LogMaxFile            = or(5, 0)
	IgnoreDnsErrorLog     atomic.Bool
	IgnoreTimeoutErrorLog atomic.Bool

	DNSCache = or[uint](1024, 256)

	ProcessDumper = or(true, false)

	Timeout         = time.Second * 16
	ResolverTimeout = time.Second * 10

	SnifferBufferSize = pool.DefaultSize

	UDPBatchSize             = 8
	MaxUDPUnprocessedPackets = atomicx.NewValue(200)
	UDPBufferSize            = atomicx.NewValue(2048)
	RelayBufferSize          = atomicx.NewValue(4096)
	DNSProcessThread         = atomicx.NewValue[int64](150)

	// MPTCP has bug in linux or some server is not support which will
	//  make tcp connection reset,  we don't specific to set it, just default
	// MPTCP = true

	UDPChannelBufferSize = 1000

	IPv6 = atomicx.NewValue(true)
	// FakeIPEnabled resolver fake ip or inbound fake ip enable
	FakeIPEnabled = atomicx.NewValue(false)

	HistorySize = or[uint](1000, 500)

	DataDir = atomicx.NewValue(DefaultConfigDir())

	ProxyChain    = netapi.NewDynamicProxy(netapi.NewErrProxy(errors.New("not initialized")))
	ResolverChain = netapi.NewDynamicResolver(netapi.Bootstrap())
)

func DefaultConfigDir() (Path string) {
	var err error
	Path, err = os.UserConfigDir()
	if err == nil {
		return filepath.Join(Path, "yuhaiin")
	}

	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/yuhaiin"
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
