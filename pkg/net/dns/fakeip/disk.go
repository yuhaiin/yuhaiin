package fakeip

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	ypool "github.com/Asutorufa/yuhaiin/pkg/pool"
)

const (
	// cursorKey is a special key used to store the current cursor state (index and IP).
	cursorKey = "reserved_cursor_state"
)

type DiskFakeIPPool struct {
	current netip.Addr // The current IP pointer

	cache cache.Cache

	prefix netip.Prefix
	index  uint64 // The current index relative to the start of the sequence
	maxNum uint64 // Maximum number of IPs to cache (limit for large subnets like IPv6)

	mu sync.Mutex
}

// NewDiskFakeIPPool creates a new pool.
// maxNum limits the maximum number of cached IPs.
// If maxNum <= 0, it defaults to 65536.
// If the subnet size is smaller than maxNum, maxNum is automatically adjusted to the subnet size.
func NewDiskFakeIPPool(prefix netip.Prefix, db cache.Cache, maxNum int) *DiskFakeIPPool {
	if maxNum <= 0 {
		maxNum = 65536
	}

	// Calculate the total number of IPs in the prefix.
	// We need to calculate how many bits are available for the host part.
	hostBits := prefix.Addr().BitLen() - prefix.Bits()

	// If hostBits >= 64, the size exceeds uint64 range (e.g., IPv6 /64).
	// In that case, the subnet is definitely larger than any int maxNum, so we skip the check.
	if hostBits < 64 {
		totalIPs := uint64(1) << hostBits
		if uint64(maxNum) > totalIPs {
			maxNum = int(totalIPs)
		}
	}

	pool := &DiskFakeIPPool{
		prefix: prefix,
		maxNum: uint64(maxNum),
		cache:  db.NewCache(prefix.String()),
		// Initialize to the address before the first valid one,
		// so the first Next() call lands on the first valid address.
		current: prefix.Addr().Prev(),
		index:   0,
	}

	// Restore the previous cursor state to prevent overwriting recent IPs after restart.
	pool.loadCursor()

	return pool
}

// loadCursor attempts to restore the cursor state (IP and Index) from the cache.
func (n *DiskFakeIPPool) loadCursor() {
	val, err := n.cache.Get([]byte(cursorKey))
	if err != nil || val == nil {
		return
	}
	defer ypool.PutBytes(val)

	// Format: [8 bytes index][IP bytes...]
	if len(val) <= 8 {
		return
	}

	n.index = binary.BigEndian.Uint64(val[:8])

	if addr, ok := netip.AddrFromSlice(val[8:]); ok {
		if n.prefix.Contains(addr) {
			n.current = addr
		}
	}
}

// saveCursor persists the current cursor state to the cache.
func (n *DiskFakeIPPool) saveCursor() {
	buf := make([]byte, 8+16) // 8 bytes for uint64, up to 16 bytes for IP
	binary.BigEndian.PutUint64(buf[:8], n.index)

	ipBytes := n.current.AsSlice()
	data := append(buf[:8], ipBytes...)

	err := n.cache.Put([]byte(cursorKey), data)
	if err != nil {
		log.Warn("save fake ip cursor failed", "err", err)
	}
}

func (n *DiskFakeIPPool) getIP(s string) (netip.Addr, bool) {
	key := []byte(s)
	z, err := n.cache.Get(key)
	if err == nil && z != nil {
		defer ypool.PutBytes(z)
		if addr, ok := netip.AddrFromSlice(z); ok {
			return addr, true
		}
		// Data corruption or invalid format, clean it up.
		_ = n.cache.Delete(key)
	}
	return netip.Addr{}, false
}

// store saves the mapping. If the IP was previously assigned to another domain,
// the old mapping is removed to prevent conflicts.
func (n *DiskFakeIPPool) store(domain string, addr netip.Addr) {
	addrBytes := addr.AsSlice()
	domainBytes := []byte(domain)

	err := n.cache.Batch(func(txn cache.Batch) error {
		// 1. Check if this IP is already owned by another domain (Collision/Eviction).

		if oldDomainBytes, _ := txn.Get(addrBytes); oldDomainBytes != nil {
			defer ypool.PutBytes(oldDomainBytes)
			if !bytes.Equal(oldDomainBytes, domainBytes) {
				// Delete the forward mapping: OldDomain -> IP.
				// The backward mapping (IP -> OldDomain) will be overwritten below.
				return txn.Delete(oldDomainBytes)
			}
			return nil
		}

		// 2. Save the bidirectional mapping.
		// Forward: Domain -> IP
		if err := txn.Put(domainBytes, addrBytes, cache.WithTTL(time.Hour*24)); err != nil {
			return err
		}
		// Backward: IP -> Domain
		if err := txn.Put(addrBytes, domainBytes, cache.WithTTL(time.Hour*24)); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		log.Warn("put fake ip to cache failed", "err", err)
	}
}

func (n *DiskFakeIPPool) GetFakeIPForDomain(s string) netip.Addr {
	// 1. Fast path: check cache.
	if z, ok := n.getIP(s); ok {
		return z
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Double check after lock.
	if z, ok := n.getIP(s); ok {
		return z
	}

	// 2. Allocate new IP (Round-Robin).
	// We no longer loop to find an empty slot. We force allocation based on the cursor.
	n.rotateNext()

	// 3. Store mapping and handle evictions.
	n.store(s, n.current)

	// 4. Persist cursor state.
	n.saveCursor()

	return n.current
}

// rotateNext advances the cursor to the next position.
// It wraps around if it exceeds the subnet range or the maxNum limit.
func (n *DiskFakeIPPool) rotateNext() {
	next := n.current.Next()
	n.index++

	// Reset if:
	// 1. We reached the end of the subnet.
	// 2. We exceeded the user-defined maximum count (crucial for IPv6).
	if !n.prefix.Contains(next) || n.index > n.maxNum {
		n.current = n.prefix.Addr() // Reset to start of subnet
		n.index = 1
	} else {
		n.current = next
	}
}

func (n *DiskFakeIPPool) GetDomainFromIP(ip netip.Addr) (string, bool) {
	if !n.prefix.Contains(ip) {
		return "", false
	}

	// Note: We assume the collision probability between an IP byte slice
	// and the 'cursorKey' string is negligible.
	domain, err := n.cache.Get(ip.AsSlice())
	if err != nil || domain == nil {
		return "", false
	}
	defer ypool.PutBytes(domain)

	return string(domain), true
}

func (n *DiskFakeIPPool) Prefix() netip.Prefix {
	return n.prefix
}
