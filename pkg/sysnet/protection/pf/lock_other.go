//go:build !unix

package pf

func lockConf(string) (func(), error) { return func() {}, nil }
