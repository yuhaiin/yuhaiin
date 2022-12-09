package utils

import (
	_ "net/url"
	_ "unsafe"
)

//go:linkname GetScheme net/url.getScheme
func GetScheme(ur string) (scheme, etc string, err error)

func ExistInSlice[T any](z []T, f func(T) bool) bool {
	for i := range z {
		if f(z[i]) {
			return true
		}
	}

	return false
}

func DeleteSliceElem[T any](z []T, f func(T) bool) []T {
	for i := range z {
		if f(z[i]) {
			return append(z[:i], z[i+1:]...)
		}
	}

	return z
}
