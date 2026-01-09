package v1

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/singleflight"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

//go:embed tcplife.bt
var tcplifeBt []byte

type socket struct {
	srcaddr netip.AddrPort
	dstaddr netip.AddrPort
}

type pidEntry struct {
	cmd  string
	pid  int
	uid  int
	time int64
}

type BpfTcp struct {
	tcpconnect   *exec.Cmd
	timer        *time.Timer
	singleflight singleflight.Group[socket, struct{}]
	cache        syncmap.SyncMap[socket, pidEntry]
	active       atomic.Bool
}

func (b *BpfTcp) startBpfTcp() error {
	cmd := exec.Command("bpftrace", "-")

	cmd.Stdin = bytes.NewBuffer(tcplifeBt)

	r, w := io.Pipe()

	cmd.Stdout = w
	cmd.Stderr = w

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Warn("bpftrace", "err", err, "status", cmd.ProcessState)
		}

		w.CloseWithError(err)

		log.Warn("bpf tcp exited, fallback to tranditional method", "err", err)
		b.active.Store(false)
	}()

	go func() {
		scan := bufio.NewScanner(pool.GetBufioReader(r, 2048))

		if !scan.Scan() {
			return
		}

		b.active.Store(true)
		b.processLogs(scan.Bytes())

		for scan.Scan() {
			b.processLogs(scan.Bytes())
		}
	}()

	b.tcpconnect = cmd

	return nil
}

func (b *BpfTcp) processLogs(data []byte) {
	/*
		printf("connect %d %d %s %d %s %d %s\n", pid, uid, $saddr, $lport, $daddr, $dport, comm);
	*/

	var cmd string
	var pid, uid int
	var lport, dport uint16
	var saddrstr, daddrstr string
	var comm string

	sep := unsafe.String(unsafe.SliceData(data), len(data))

	_, err := fmt.Sscan(sep, &cmd, &pid, &uid, &saddrstr, &lport, &daddrstr, &dport, &comm)
	if err != nil {
		log.Warn("scan failed", "sep", sep, "err", err)
		return
	}

	saddr, err := netip.ParseAddr(saddrstr)
	if err != nil {
		log.Warn("parse saddr failed", "saddr", saddrstr, "err", err)
		return
	}
	saddr = saddr.Unmap()

	daddr, err := netip.ParseAddr(daddrstr)
	if err != nil {
		log.Warn("parse daddr failed", "daddr", daddrstr, "err", err)
		return
	}
	daddr = daddr.Unmap()

	switch cmd {
	case "connect":
		key := socket{
			srcaddr: netip.AddrPortFrom(saddr, lport),
			dstaddr: netip.AddrPortFrom(daddr, dport),
		}

		_, _, _ = b.singleflight.Do(key, func() (struct{}, error) {
			_, _, _ = b.cache.LoadOrCreate(key, func() (pidEntry, error) {
				return pidEntry{
					pid:  pid,
					uid:  uid,
					cmd:  sep,
					time: system.CheapNowNano(),
				}, nil
			})

			return struct{}{}, nil
		})
	case "close":
		src := netip.AddrPortFrom(saddr, lport)
		dst := netip.AddrPortFrom(daddr, dport)

		b.cache.Delete(socket{src, dst})
		b.cache.Delete(socket{dst, src})
	}
}
