package common

import (
	"net"
	"time"
)

func Forward(src, dst net.Conn) {
	CloseSig := CloseSigPool.Get().(chan error)
	go pipe(src, dst, CloseSig)
	go pipe(dst, src, CloseSig)
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
