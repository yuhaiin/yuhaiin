package assert

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

func NoError(t testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("%s:%d: %v\n", file, line, err)
		t.FailNow()
	}
}

func Equal[T comparable](t testing.TB, expected, actual T) {
	if expected != actual {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("%s:%d: expected %v, but got %v\n", file, line, expected, actual)
	}
}
func MustEqual[T comparable](t testing.TB, expected, actual T) {
	if expected != actual {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("%s:%d: expected %v, but got %v\n", file, line, expected, actual)
		t.FailNow()
	}
}

func ObjectsAreEqual(expected, actual any) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}

	exp, ok := expected.([]byte)
	if !ok {
		return reflect.DeepEqual(expected, actual)
	}

	act, ok := actual.([]byte)
	if !ok {
		return false
	}
	if exp == nil || act == nil {
		return exp == nil && act == nil
	}
	return bytes.Equal(exp, act)
}
