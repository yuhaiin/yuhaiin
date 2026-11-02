package localwrap

import (
	"net/netip"
	"os"
)

const DefaultSocket = "/run/yuhaiin/wrap.sock"

// Config enables a local endpoint for one trusted, non-root Unix account.
type Config struct {
	Socket       string
	UID          uint32
	GID          uint32
	CgroupRoot   string
	IPv6         bool
	MaxSessions  int
	FakeIPSource interface {
		SubscribeFakeIPRanges(func([2]netip.Prefix) error) (func(), error)
	}
}

// Options describes a local launch. Nil environment and empty directory inherit
// the caller's values. Files remain caller-owned. Terminal mode uses a new PTY.
type Options struct {
	Socket                string
	Argv                  []string
	Env                   []string
	Dir                   string
	Stdin, Stdout, Stderr *os.File
	Terminal              bool
}
