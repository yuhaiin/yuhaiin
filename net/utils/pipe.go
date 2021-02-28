package utils

import (
	"io"
	"net"
)

//Forward pipe
func Forward(src, dst net.Conn) {
	CloseSig := CloseSigPool.Get().(chan error)
	go pipe(dst, src, CloseSig)
	go pipe(src, dst, CloseSig)
	<-CloseSig
	<-CloseSig
	CloseSigPool.Put(CloseSig)
}

//SingleForward single pipe
func SingleForward(src io.Reader, dst io.Writer) (err error) {
	CloseSig := CloseSigPool.Get().(chan error)
	go pipe(src, dst, CloseSig)
	err = <-CloseSig
	CloseSigPool.Put(CloseSig)
	return
}

func pipe(src io.Reader, dst io.Writer, closeSig chan error) {
	buf := BuffPool.Get().([]byte)
	defer func() {
		BuffPool.Put(buf)
	}()
	for {
		n, err := src.Read(buf[0:])
		if err != nil {
			closeSig <- err
			return
		}

		_, err = dst.Write(buf[0:n])
		if err != nil {
			closeSig <- err
			return
		}

	}
}
