//go:build !darwin

package helper

func joinSocketGroup(int) (bool, string) { return false, "not supported on this platform" }
