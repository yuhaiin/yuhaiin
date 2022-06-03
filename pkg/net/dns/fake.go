package dns

import (
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type Fake struct {
	domainToIP *utils.LRU[string, string]
	ipRange    *net.IPNet

	mu sync.Mutex
}

func NewFake(ipRange *net.IPNet) *Fake {
	ones, bits := ipRange.Mask.Size()
	lruSize := int(math.Pow(2, float64(bits-ones)) - 1)
	// if lruSize > 250 {
	// 	lruSize = 250
	// }
	return &Fake{
		ipRange:    ipRange,
		domainToIP: utils.NewLru[string, string](lruSize, 0*time.Minute),
	}
}

// GetFakeIPForDomain checks and generates a fake IP for a domain name
func (fkdns *Fake) GetFakeIPForDomain(domain string) string {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	if v, ok := fkdns.domainToIP.Load(domain); ok {
		return v
	}
	currentTimeMillis := uint64(time.Now().UnixNano() / 1e6)
	ones, bits := fkdns.ipRange.Mask.Size()
	rooms := bits - ones
	if rooms < 64 {
		currentTimeMillis %= (uint64(1) << rooms)
	}
	bigIntIP := big.NewInt(0).SetBytes(fkdns.ipRange.IP)
	bigIntIP = bigIntIP.Add(bigIntIP, new(big.Int).SetUint64(currentTimeMillis))
	var ip net.IP
	for {
		ip = net.IP(bigIntIP.Bytes())

		// if we run for a long time, we may go back to beginning and start seeing the IP in use
		if ok := fkdns.domainToIP.ValueExist(ip.String()); !ok {
			break
		}

		bigIntIP = bigIntIP.Add(bigIntIP, big.NewInt(1))
		if !fkdns.ipRange.Contains(bigIntIP.Bytes()) {
			bigIntIP = big.NewInt(0).SetBytes(fkdns.ipRange.IP)
		}
	}
	fkdns.domainToIP.Add(domain, ip.String())
	return ip.String()
}

func (fkdns *Fake) GetDomainFromIP(ip string) (string, bool) {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	return fkdns.domainToIP.ValueLoad(ip)
}

var _ dns.DNS = (*FakeDNS)(nil)

type FakeDNS struct {
	upStream dns.DNS
	pool     *Fake
}

func WrapFakeDNS(upStream dns.DNS, pool *Fake) *FakeDNS {
	return &FakeDNS{upStream: upStream, pool: pool}
}
func (f *FakeDNS) LookupIP(domain string) ([]net.IP, error) {
	ip := f.pool.GetFakeIPForDomain(domain)
	log.Println("map", ip, "to", domain)
	return []net.IP{net.ParseIP(ip).To4()}, nil
}

func (f *FakeDNS) LookupPtr(name string) (string, error) {
	var ip string

	if i := strings.Index(name, ".in-addr.arpa."); i != -1 {
		p := strings.Split(name[:i], ".")
		for i := 3; i >= 0; i-- {
			ip += p[i]
			if i != 0 {
				ip += "."
			}
		}
	} else if i := strings.Index(name, ".ip6.arpa."); i != -1 {
		p := strings.Split(name[:i], ".")
		count := 0
		for i := 31; i >= 0; i-- {
			ip += p[i]
			count++
			if count == 4 && i != 0 {
				ip += ":"
				count = 0
			}
		}
	}

	r, ok := f.pool.GetDomainFromIP(ip)
	if !ok {
		return "", fmt.Errorf("not found %s[%s] ptr", ip, name)
	}

	return r, nil
}

func (f *FakeDNS) Do(b []byte) ([]byte, error) { return f.upStream.Do(b) }

func (f *FakeDNS) Close() error { return nil }
