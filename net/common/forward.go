package common

import (
	"net"
	"time"
)

var (
	DownloadTotal = 0.0
	UploadTotal   = 0.0
	// mode = 0 download mode = 1 upload
	queue = make(chan struct {
		mode int
		num  int
	}, 100)
)

func init() {
	go func() {
		for s := range queue {
			switch s.mode {
			case 0:
				DownloadTotal += float64(s.num) / 1024.0 / 1024.0
			case 1:
				UploadTotal += float64(s.num) / 1024.0 / 1024.0
			}
		}
	}()
}

func Forward(src, dst net.Conn) {
	CloseSig := CloseSigPool.Get().(chan error)
	go pipeStatistic(src, dst, CloseSig, 1)
	go pipeStatistic(dst, src, CloseSig, 0)
	<-CloseSig
	<-CloseSig
	CloseSigPool.Put(CloseSig)
}

func pipe(src, dst net.Conn, closeSig chan error) {
	buf := BuffPool.Get().([]byte)
	for {
		n, err := src.Read(buf[0:])
		if err != nil {
			closeSig <- err
			BuffPool.Put(buf[:cap(buf)])
			_ = src.SetDeadline(time.Now())
			_ = dst.SetDeadline(time.Now())
			return
		}

		n, err = dst.Write(buf[0:n])
		if err != nil {
			closeSig <- err
			BuffPool.Put(buf[:cap(buf)])
			_ = src.SetDeadline(time.Now())
			_ = dst.SetDeadline(time.Now())
			return
		}

	}
}

func pipeStatistic(src, dst net.Conn, closeSig chan error, mode int) {
	buf := BuffPool.Get().([]byte)
	for {
		n, err := src.Read(buf[0:])
		if err != nil {
			closeSig <- err
			BuffPool.Put(buf[:cap(buf)])
			_ = src.SetDeadline(time.Now())
			_ = dst.SetDeadline(time.Now())
			return
		}
		go func() {
			queue <- struct {
				mode int
				num  int
			}{mode: mode, num: n}
		}()

		n, err = dst.Write(buf[0:n])
		if err != nil {
			closeSig <- err
			BuffPool.Put(buf[:cap(buf)])
			_ = src.SetDeadline(time.Now())
			_ = dst.SetDeadline(time.Now())
			return
		}
	}
}

func pipeStatistic2(src, dst net.Conn, closeSig chan error) {
	buf := BuffPool.Get().([]byte)
	for {
		n, err := src.Read(buf[0:])
		if err != nil {
			closeSig <- err
			BuffPool.Put(buf[:cap(buf)])
			_ = src.SetDeadline(time.Now())
			_ = dst.SetDeadline(time.Now())
			return
		}
		queue <- struct {
			mode int
			num  int
		}{mode: 1, num: n}

		_, err = dst.Write(buf[0:n])
		if err != nil {
			closeSig <- err
			BuffPool.Put(buf[:cap(buf)])
			_ = src.SetDeadline(time.Now())
			_ = dst.SetDeadline(time.Now())
			return
		}
	}
}
