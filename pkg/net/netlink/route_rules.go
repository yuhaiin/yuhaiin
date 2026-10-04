package netlink

import "sync"

// sharedRouteRules keeps shared platform routing rules alive until their last
// TUN releases them. Borrowed rules are never removed; failed removal is retried
// by the releasing TUN without discarding its lease.
type sharedRouteRules struct {
	mu     sync.Mutex
	leases map[int]*ruleLease
}

type ruleLease struct {
	users int
	owned bool
}

func (r *sharedRouteRules) acquire(key int, create func() (bool, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if lease := r.leases[key]; lease != nil {
		lease.users++
		return nil
	}
	owned, err := create()
	if err != nil {
		return err
	}
	if r.leases == nil {
		r.leases = make(map[int]*ruleLease)
	}
	r.leases[key] = &ruleLease{users: 1, owned: owned}
	return nil
}

func (r *sharedRouteRules) release(key int, remove func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	lease := r.leases[key]
	if lease == nil {
		return nil
	}
	if lease.users > 1 {
		lease.users--
		return nil
	}
	if lease.owned {
		if err := remove(); err != nil {
			return err
		}
	}
	delete(r.leases, key)
	return nil
}
