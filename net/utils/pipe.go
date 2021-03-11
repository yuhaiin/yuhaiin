package utils

import (
	"io"
	"net"
)

//Forward pipe
func Forward(src, dst net.Conn) {
	CloseSig := CloseSigPool.Get().(chan error)
	go func() {
		CloseSig <- pipe(dst, src)
	}()
	_ = pipe(src, dst)
	<-CloseSig
	CloseSigPool.Put(CloseSig)
}

//SingleForward single pipe
func SingleForward(src io.Reader, dst io.Writer) (err error) {
	return pipe(src, dst)
}

func pipe(src io.Reader, dst io.Writer) error {
	buf := BuffPool.Get().([]byte)
	defer func() {
		BuffPool.Put(buf)
	}()
	for {
		n, err := src.Read(buf[0:])
		if err != nil {
			return err
		}

		_, err = dst.Write(buf[0:n])
		if err != nil {
			return err
		}
	}
}
