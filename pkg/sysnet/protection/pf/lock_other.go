//go:build !unix

package pf

func lockConf(string) (func(), error) { return func() {}, nil }

// syncDir: Windows cannot sync a directory handle; NTFS journals the
// rename itself.
func syncDir(string) error { return nil }
