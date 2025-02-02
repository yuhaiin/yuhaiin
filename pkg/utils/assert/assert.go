package assert

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"
)

func NoError(t testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		t.Logf("%s:%d: %v\n", file, line, err)
		t.FailNow()
	}
}

func Error(t testing.TB, err error) {
	if err == nil {
		_, file, line, _ := runtime.Caller(1)
		t.Logf("%s:%d: expected error, but got nil\n", file, line)
		t.FailNow()
	}
}

func Equal[T comparable](t testing.TB, expected, actual T, msgs ...any) {
	if expected != actual {
		_, file, line, _ := runtime.Caller(1)
		t.Logf("%s:%d: expected %v, but got %v, %v\n", file, line, expected, actual, msgs)
	}
}
func MustEqual[T any](t testing.TB, expected, actual T) {
	if !ObjectsAreEqual(expected, actual) {
		_, file, line, _ := runtime.Caller(1)
		t.Logf("%s:%d: expected %v, but got %v\n", file, line, expected, actual)
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
