package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var (
	MaxSegmentSize = pool.MaxSegmentSize
)

func udpIdleTimeout() time.Duration {
	return configuration.UDPIdleTimeout.Load()
}

type authenticatedSourceKey struct {
	credentialID, inboundID string
	source                  uint64
}
type Table struct {
	access               netapi.TrafficAccess
	authenticatedSources syncmap.SyncMap[authenticatedSourceKey, *SourceControl]
	dialer               netapi.Proxy
	sniffer              netapi.PacketSniffer

	cleanerWake    chan struct{}
	sourceControl  syncmap.SyncMap[uint64, *SourceControl]
	trafficControl trafficcontrol.PolicyResolver
	budget         trafficcontrol.Budget
	closed         atomic.Bool
	mu             sync.RWMutex // Serializes queue admission with Close.
	stop           chan struct{}
	done           chan struct{}
	closeOnce      sync.Once
}

var ErrNATSessionLimit = errors.New("udp nat: session limit")

// SetTrafficAccess is called during ingress construction, before packet
// admission starts. Runtime updates publish through this same capability.
func (t *Table) SetTrafficAccess(access netapi.TrafficAccess) { t.access = access }

// SetTrafficControl injects the optional server-owned controller during ingress
// construction, before any packets or resource queries are admitted.
func (t *Table) SetTrafficControl(control trafficcontrol.PolicyResolver, budget trafficcontrol.Budget) {
	t.trafficControl = control
	if budget != nil {
		t.budget = budget
	}
}

// ResourceStats exposes live NAT sessions and charged queue bytes.
func (t *Table) ResourceStats() trafficcontrol.Counters { return t.budget.Snapshot() }

func NewTable(sniffer netapi.PacketSniffer, dialer netapi.Proxy) *Table {
	return NewTableWithControl(sniffer, dialer, trafficcontrol.NewDatagramBudget(nil), nil)
}

// NewTableWithControl injects engine-owned policy and resource capabilities.
// The source/migration key and outbound socket remain owned by NAT.
func NewTableWithControl(sniffer netapi.PacketSniffer, dialer netapi.Proxy, budget trafficcontrol.Budget, policies trafficcontrol.PolicyResolver) *Table {
	if budget == nil {
		budget = trafficcontrol.UnlimitedBudget()
	}
	t := &Table{
		dialer:         dialer,
		sniffer:        sniffer,
		cleanerWake:    make(chan struct{}, 1),
		budget:         budget,
		trafficControl: policies,
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}

	go t.runCleaner(udpIdleTimeout)

	return t
}

// Suspend cleanup while the NAT table is empty. Only publishing a new source
// starts the timer; existing sources do not signal it on each packet.
func (t *Table) runCleaner(interval func() time.Duration) {
	defer close(t.done)
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	arm := func() {
		if timer == nil {
			timer = time.NewTimer(interval())
		} else {
			timer.Reset(interval())
		}
		timerC = timer.C
	}
	for {
		select {
		case <-t.stop:
			return
		case <-t.cleanerWake:
			if timerC == nil {
				arm()
			}
		case <-timerC:
			timerC = nil
			idleTimeout := interval()
			for k, v := range t.sourceControl.Range {
				if v.retireIdle(idleTimeout) && t.sourceControl.CompareAndDelete(k, v) {
					if err := v.Close(); err != nil {
						log.Error("close source control failed", "err", err)
					}
				}
			}
			for k, v := range t.authenticatedSources.Range {
				if (!v.identityValid() || v.retireIdle(idleTimeout)) && t.authenticatedSources.CompareAndDelete(k, v) {
					_ = v.Close()
				}
			}
			for range t.authenticatedSources.RangeValues {
				arm()
				break
			}
			for range t.sourceControl.RangeValues {
				arm()
				break
			}
		}
	}
}

func (u *Table) Write(ctx context.Context, pkt *netapi.Packet) error {
	metrics.Counter.AddSendUDPPacket()
	metrics.Counter.AddSendUDPPacketSize(len(pkt.GetPayload()))

	if u.closed.Load() {
		return fmt.Errorf("udp nat table: %w", net.ErrClosed)
	}

	key := pkt.MigrateID

	if key == 0 {
		srcAddr, err := netapi.ParseSysAddr(pkt.Src())
		if err != nil {
			return fmt.Errorf("parse src addr failed: %w", err)
		}

		key = srcAddr.Comparable()
	}

	if !pkt.Identity.Valid() {
		return context.Canceled
	}
	load := func(create func() (*SourceControl, error)) (*SourceControl, bool, error) {
		return u.sourceControl.LoadOrCreate(key, create)
	}
	remove := func(source *SourceControl) { u.sourceControl.CompareAndDelete(key, source) }
	if identity := pkt.Identity; identity != nil || u.access != nil {
		credential := ""
		if identity != nil {
			credential = identity.CredentialID
		}
		scoped := authenticatedSourceKey{credential, pkt.InboundID(), key}
		load = func(create func() (*SourceControl, error)) (*SourceControl, bool, error) {
			return u.authenticatedSources.LoadOrCreate(scoped, create)
		}
		remove = func(source *SourceControl) { u.authenticatedSources.CompareAndDelete(scoped, source) }
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.closed.Load() {
		return fmt.Errorf("udp nat table: %w", net.ErrClosed)
	}
	for {
		if !pkt.Identity.Valid() {
			return context.Canceled
		}
		r, loaded, err := load(func() (*SourceControl, error) {
			var resources *trafficcontrol.ResourceSession
			if identity := pkt.Identity; identity != nil {
				var ok bool
				resources, ok = trafficcontrol.AcquireIdentityResources(u.trafficControl, identity.UserID, identity.CredentialID, true)
				if !ok {
					return nil, ErrNATSessionLimit
				}
			}
			lease, ok := u.budget.AcquireSession()
			if !ok {
				resources.Release()
				return nil, ErrNATSessionLimit
			}
			lease = trafficcontrol.BindSessionResources(lease, resources)
			source, err := newSourceChanWithAccess(u.sniffer, u.dialer, lease, u.budget, u.trafficControl, u.access, netapi.TrafficSubject{Identity: pkt.Identity, InboundID: pkt.InboundID(), External: true})
			if err != nil {
				return nil, err
			}
			if pkt.Identity != nil {
				source.bindIdentity(pkt.Identity)
			}
			return source, nil
		})
		if err != nil {
			return err
		}
		if !loaded {
			select {
			case u.cleanerWake <- struct{}{}:
			default:
			}
		}
		err = r.WritePacket(ctx, pkt)
		if !errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return err
		}
		// Cleanup can retire a control between lookup and admission. Retry the
		// same source mapping; never add the destination to the full-cone key.
		remove(r)
		// Join the retired owner before reserving its replacement. Its worker
		// returns the session lease even when the cleaner loses map deletion.
		_ = r.Close()
	}
}

func (u *Table) Close() error {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		u.closed.Store(true)
		close(u.stop)
		var controls []*SourceControl
		for v := range u.sourceControl.RangeValues {
			controls = append(controls, v)
		}
		u.sourceControl.Clear()
		for source := range u.authenticatedSources.RangeValues {
			controls = append(controls, source)
		}
		u.authenticatedSources.Clear()
		u.mu.Unlock()
		// No writer can publish another control after the snapshot above.
		// Wait outside mu because closing a control may interrupt network I/O.
		for _, v := range controls {
			v.close()
		}
		for _, v := range controls {
			_ = v.Close()
		}
		<-u.done
	})
	return nil
}
