package common

import (
	"net"
	"sync/atomic"
	"time"
)

var (
	DownloadTotal = int64(0)
	UploadTotal   = int64(0)
	// int[0] is mode: mode = 0 -> download , mode = 1 -> upload
	queue = make(chan [2]int64, 10)
)

func init() {
	go func() {
		for s := range queue {
			switch s[0] {
			case 0:
				atomic.AddInt64(&DownloadTotal, s[1])
				//DownloadTotal += s[1]
			case 1:
				atomic.AddInt64(&UploadTotal, s[1])
				//UploadTotal += s[1]
			}
			QueuePool.Put(s)
		}
	}()
}

func Forward(src, dst net.Conn) {
	CloseSig := CloseSigPool.Get().(chan error)
	go pipeStatistic(dst, src, CloseSig, 0)
	go pipeStatistic(src, dst, CloseSig, 1)
	<-CloseSig
	<-CloseSig
	CloseSigPool.Put(CloseSig)
}

func pipe(src, dst net.Conn, closeSig chan error) {
	buf := BuffPool.Get().([]byte)
	defer func() {
		BuffPool.Put(buf[:cap(buf)])
		_ = src.SetDeadline(time.Now())
		_ = dst.SetDeadline(time.Now())
	}()
	for {
		n, err := src.Read(buf[0:])
		if err != nil {
			closeSig <- err
			return
		}

		n, err = dst.Write(buf[0:n])
		if err != nil {
			closeSig <- err
			return
		}

	}
}

func pipeStatistic(src, dst net.Conn, closeSig chan error, mode int64) {
	var n int
	var err error
	buf := BuffPool.Get().([]byte)
	defer func() {
		closeSig <- err
		BuffPool.Put(buf[:cap(buf)])
		_ = src.SetDeadline(time.Now())
		_ = dst.SetDeadline(time.Now())
	}()

	for {
		if n, err = src.Read(buf[0:]); err != nil {
			return
		}

		go func() {
			x := QueuePool.Get().([2]int64)
			x[0] = mode
			x[1] = int64(n)
			queue <- x
		}()

		if _, err = dst.Write(buf[0:n]); err != nil {
			return
		}
	}
}
