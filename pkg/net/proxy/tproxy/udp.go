package tproxy

import (
	"log"
	"syscall"
)

func control() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var fn = func(s uintptr) {
			err := syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			if err != nil {
				log.Printf("set socket with SOL_IP, IP_TRANSPARENT failed: %v", err)
			}

			val, err := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT)
			if err != nil {
				log.Printf("get socket with SOL_IP, IP_TRANSPARENT failed: %v", err)
			} else {
				log.Printf("value of IP_TRANSPARENT option is: %d", int(val))
			}

			err = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
			if err != nil {
				log.Printf("set socket with SOL_IP, IP_RECVORIGDSTADDR failed: %v", err)
			}

			val, err = syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR)
			if err != nil {
				log.Printf("get socket with SOL_IP, IP_RECVORIGDSTADDR failed: %v", err)
			} else {
				log.Printf("value of IP_RECVORIGDSTADDR option is: %d", int(val))
			}
		}

		if err := c.Control(fn); err != nil {
			return err
		}

		return nil
	}
}
