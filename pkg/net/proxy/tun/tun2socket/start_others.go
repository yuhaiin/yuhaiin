//go:build !linux
// +build !linux

package tun2socket

import (
	"fmt"
	"io"
	"runtime"
)

func openDevice(name string) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("unsupported os %v", runtime.GOOS)
}
