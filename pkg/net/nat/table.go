package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var IdleTimeout = time.Minute * 3 / 2
var MaxSegmentSize = pool.MaxSegmentSize

func NewTable(dialer netapi.Proxy) *Table {
	return &Table{dialer: dialer}
}

type Table struct {
	dialer netapi.Proxy
	sf     singleflight.GroupNoblock[string, *SourceTable]
	cache  syncmap.SyncMap[string, *SourceTable]
}

func (u *Table) write(ctx context.Context, t *SourceTable, pkt *netapi.Packet, alreadyBackground bool) error {
	key := pkt.Dst.String()

	var err error
	// ! we need write to same ip when use fakeip/domain, eg: quic will need it to create stream
	udpAddr, ok := loadSourceTableAddr[*net.UDPAddr](t, cacheTypeUDPAddr, key)
	if ok {
		_, err = t.WriteTo(pkt.Payload, udpAddr)
		pool.PutBytes(pkt.Payload)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}

	store := netapi.GetContext(ctx)
	store.Resolver = t.resolver

	// cache fakeip/hosts/bypass address
	// because domain bypass maybe resolve domain which is speed some time, so we cache it for a while
	dstAddr, ok := loadSourceTableAddr[netapi.Address](t, cacheTypeDispatch, key)
	if !ok {
		store.SkipRoute = true

		dstAddr, err = u.dialer.Dispatch(ctx, pkt.Dst)
		if err != nil {
			return fmt.Errorf("dispatch addr failed: %w", err)
		}

		if key != dstAddr.String() {
			t.storeAddr(cacheTypeDispatch, key, dstAddr)
		}
	}

	// check is need resolve
	if !dstAddr.IsFqdn() || t.skipResolve {
		_, err = t.WriteTo(pkt.Payload, dstAddr)
		pool.PutBytes(pkt.Payload)
		if err == nil {
			t.mapAddr(dstAddr, pkt.Dst)
		}
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}

	//
	// --------- proxy domain ------
	//

	write := func(ctx context.Context) error {
		defer pool.PutBytes(pkt.Payload)
		var err error
		udpAddr, err, _ := t.sf.Do(key, func() (*net.UDPAddr, error) {
			udpAddr, err := netapi.ResolveUDPAddr(ctx, dstAddr)
			if err != nil {
				return nil, err
			}
			t.storeAddr(cacheTypeUDPAddr, key, udpAddr)
			t.mapAddr(udpAddr, pkt.Dst)
			return udpAddr, nil
		})
		if err != nil {
			return err
		}

		_, err = t.WriteTo(pkt.Payload, udpAddr)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}

	if alreadyBackground {
		return write(ctx)
	}

	// if need resolve, make it run in background
	go func() {
		ctx = context.WithoutCancel(ctx)
		ctx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		if err := write(ctx); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error("nat table write to remote", "err", err)
		}
	}()
	return nil
}

func (u *Table) Write(ctx context.Context, pkt *netapi.Packet) error {
	metrics.Counter.AddSendUDPPacket()

	pkt = pkt.Clone()

	var key string

	if pkt.MigrateID != 0 {
		key = strconv.FormatUint(pkt.MigrateID, 10)
	} else {
		key = pkt.Src.String()
	}

	t, ok := u.cache.Load(key)
	if ok && t.connected.Load() {
		return u.write(ctx, t, pkt, false)
	}

	ctx = context.WithoutCancel(ctx)

	u.sf.DoBackground(
		key,
		func(st *SourceTable) {
			ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
			defer cancel()
			if err := u.write(ctx, st, pkt, true); err != nil {
				log.Error("udp remote to local", "err", err)
			}
		},
		func() (*SourceTable, bool) {
			store := netapi.GetContext(ctx)
			store.Source = pkt.Src
			store.Destination = pkt.Dst
			if t != nil {
				store.UDPMigrateID = t.migrateID
				if store.UDPMigrateID != 0 {
					log.Info("set migrate id", "id", store.UDPMigrateID)
				}
			}

			ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
			defer cancel()

			dstpconn, err := u.dialer.PacketConn(ctx, pkt.Dst)
			if err != nil {
				return nil, false
			}

			var table *SourceTable = t
			if t != nil {
				if timer := t.stopTimer; timer != nil {
					timer.Stop()
				}
			} else {
				table = &SourceTable{skipResolve: store.Resolver.SkipResolve}
			}

			table.writeBack = pkt.WriteBack
			table.dstPacketConn = dstpconn
			table.migrateID = store.UDPMigrateID
			table.resolver = store.Resolver
			table.connected.Store(true)
			u.cache.Store(key, table)

			go u.runWriteBack(key, dstpconn, table)

			return table, true
		})

	return nil
}

func (u *Table) runWriteBack(key string, p net.PacketConn, table *SourceTable) {
	defer func() {
		table.stopTimer = time.AfterFunc(IdleTimeout, func() {
			u.cache.Delete(key)
		})

		table.connected.Store(false)
		p.Close()
	}()

	ch := make(chan backPacket, 250)
	defer close(ch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		defer cancel()
		table.runWriteBack(ch)
	}()

	data := pool.GetBytes(MaxSegmentSize)
	defer pool.PutBytes(data)

	for {
		_ = p.SetReadDeadline(time.Now().Add(IdleTimeout))
		n, from, err := p.ReadFrom(data)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, os.ErrDeadlineExceeded) ||
				errors.Is(err, io.EOF) {
				return
			}
			log.Error("read from proxy failed", "err", err)
			return
		}

		metrics.Counter.AddReceiveUDPPacket()

		select {
		case ch <- backPacket{from, pool.Clone(data[:n])}:
		case <-ctx.Done():
			return
		}
	}
}

func (u *Table) Close() error {
	u.cache.Range(func(_ string, value *SourceTable) bool {
		value.dstPacketConn.Close()
		return true
	})

	return nil
}
