package nat

import "syscall"

func setSocketOptions(fd uintptr) {
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_NO_CHECK, 1)
}
