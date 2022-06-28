//go:build !linux
// +build !linux

package server

func control(fd uintptr) error { return nil }
