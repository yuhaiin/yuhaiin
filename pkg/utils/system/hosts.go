package system

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
)

var (
	refreshMu        sync.Mutex
	hosts            atomic.Value
	expire           atomic.Int64
	hostsFilePath    = "/etc/hosts"
	hostsFileModTime = time.Time{}
)

const (
	hostsFileUnchangedCacheDuration = 5 * time.Second
	hostsFileCacheDuration          = 3 * time.Minute
)

func init() {
	hosts.Store(Hosts{
		ByAddr: make(map[netip.Addr][]string),
		ByName: make(map[string]byName),
	})
}

func LookupStaticHost(host string) ([]netip.Addr, string) {
	host = strings.ToLower(host)

	maybeRefresh()
	h := hosts.Load().(Hosts)
	x, ok := h.ByName[host]
	if !ok {
		return nil, ""
	}
	return x.addrs, x.canonicalName
}

func LookupStaticAddr(ip net.IP) []string {
	maybeRefresh()
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}

	h := hosts.Load().(Hosts)
	return h.ByAddr[addr.Unmap()]
}

//go:linkname IsDomainName net.isDomainName
func IsDomainName(string) bool

type byName struct {
	canonicalName string
	addrs         []netip.Addr
}

type Hosts struct {
	ByAddr map[netip.Addr][]string
	ByName map[string]byName
}

func readHosts() Hosts {
	hosts := Hosts{
		ByAddr: make(map[netip.Addr][]string),
		ByName: make(map[string]byName),
	}

	for v := range slice.RangeFileByLine(hostsFilePath) {
		f := strings.Fields(v)
		if len(f) < 2 {
			continue
		}

		addr, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}

		for i := 1; i < len(f); i++ {
			if !IsDomainName(f[i]) {
				continue
			}

			f[i] = strings.ToLower(f[i])

			hosts.ByAddr[addr] = append(hosts.ByAddr[addr], f[i])

			if v, ok := hosts.ByName[f[i]]; ok {
				hosts.ByName[f[i]] = byName{
					addrs:         append(v.addrs, addr),
					canonicalName: v.canonicalName,
				}
				continue
			}

			hosts.ByName[f[i]] = byName{
				addrs:         []netip.Addr{addr},
				canonicalName: f[i],
			}
		}
	}

	return hosts
}

func maybeRefresh() {
	// android can't change hosts without root
	// so we don't need to refresh generally
	if runtime.GOOS == "android" && expire.Load() != 0 {
		return
	}

	// Double-checked locking pattern
	exp := expire.Load()
	if CheapNowNano() <= exp {
		return
	}

	if exp == 0 {
		refreshMu.Lock()
	} else {
		if !refreshMu.TryLock() {
			return
		}
	}
	defer refreshMu.Unlock()

	now := CheapNowNano()
	if now <= expire.Load() {
		return
	}

	f, err := os.Stat(hostsFilePath)
	if err == nil && f.ModTime().Equal(hostsFileModTime) {
		// File unchanged, update expire to check again later (e.g. 5 seconds)
		// to avoid stat storm.
		expire.Store(now + hostsFileUnchangedCacheDuration.Nanoseconds())
		return
	}

	hs := readHosts()
	hosts.Store(hs)

	if err == nil {
		hostsFileModTime = f.ModTime()
	}

	expire.Store(now + hostsFileCacheDuration.Nanoseconds())
}
