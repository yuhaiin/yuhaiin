package nat

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// The destination resolver optionally pins synthetic identities for the whole
// source session, independently of the one shared outbound UDP socket.
type destinationLeaser interface {
	LeaseDestination(context.Context, netapi.Address) (func(), error)
}

type destinationLease struct {
	release  func()
	retained bool
}

func (u *SourceControl) acquireDestinationLease(ctx context.Context, addr netapi.Address) error {
	key := addr.Comparable()
	if _, ok := u.destinationLeases[key]; ok {
		return nil
	}
	release, err := u.destinationLeaser.LeaseDestination(ctx, addr)
	if err != nil {
		return err
	}
	if release == nil {
		return nil
	}
	if len(u.destinationLeases) >= maxCachedDestinations {
		release()
		return errReverseMappingFull
	}
	if u.destinationLeases == nil {
		u.destinationLeases = make(map[uint64]*destinationLease)
	}
	u.destinationLeases[key] = &destinationLease{release: release}
	return nil
}

func (u *SourceControl) retainDestinationLease(key uint64) {
	if lease := u.destinationLeases[key]; lease != nil {
		lease.retained = true
	}
}

func (u *SourceControl) releaseUnusedDestinationLease(key uint64) {
	lease := u.destinationLeases[key]
	if lease == nil || lease.retained || u.resolutions[key] != nil {
		return
	}
	lease.release()
	delete(u.destinationLeases, key)
}

func (u *SourceControl) releaseDestinationLeases() {
	for _, lease := range u.destinationLeases {
		lease.release()
	}
	clear(u.destinationLeases)
}
