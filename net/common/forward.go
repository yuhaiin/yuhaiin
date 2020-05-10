package common

import (
	"net"
	"time"
)

var (
	DownloadTotal = 0.0
	UploadTotal   = 0.0
	// int[0] is mode -> mode = 0 download mode = 1 upload
	queue = make(chan [2]int)
)

func init() {
	go func() {
		for s := range queue {
			switch s[0] {
			case 0:
				DownloadTotal += float64(s[1]) / 1024.0 / 1024.0
			case 1:
				UploadTotal += float64(s[1]) / 1024.0 / 1024.0
			}
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
			queue <- [2]int{mode, n}
		}()

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
		queue <- [2]int{1, n}

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
