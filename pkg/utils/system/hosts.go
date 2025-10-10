package system

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
)

var (
	mu    sync.Mutex
	hosts = Hosts{
		ByAddr: make(map[netip.Addr][]string),
		ByName: make(map[string]byName),
	}
	expire           int64 = 0
	hostsFilePath          = "/etc/hosts"
	hostsFileModTime       = time.Time{}
)

func LookupStaticHost(host string) ([]netip.Addr, string) {
	host = strings.ToLower(host)

	refresh()
	x, ok := hosts.ByName[host]
	if !ok {
		return nil, ""
	}
	return x.addrs, x.canonicalName
}

func LookupStaticAddr(ip net.IP) []string {
	refresh()
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}

	return hosts.ByAddr[addr.Unmap()]
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

func refresh() {
	// android can't change hosts without root
	// so we don't need to refresh generally
	if runtime.GOOS == "android" && expire != 0 {
		return
	}

	mu.Lock()
	// the go library refrsh duration is 5 seconds
	// it's too frenquently maybe
	//
	// TODO linux use inotify to refresh
	if expire == 0 || CheapNowNano() > expire {
		f, err := os.Stat(hostsFilePath)
		if err == nil && f.ModTime().Equal(hostsFileModTime) {
			mu.Unlock()
			return
		}

		hs := readHosts()
		hosts = hs
		hostsFileModTime = f.ModTime()
		expire = CheapNowNano() + (time.Minute * 3).Nanoseconds()
	}
	mu.Unlock()
}
