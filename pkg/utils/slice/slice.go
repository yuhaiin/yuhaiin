package slice

import (
	"bufio"
	"iter"
	"os"
	"strings"
)

func To[T, T2 any](from []T, f func(T) T2) []T2 {
	to := make([]T2, len(from))
	for i, v := range from {
		to[i] = f(v)
	}

	return to
}

func RangeFileByLine(path string) iter.Seq[string] {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil
	}

	return func(f func(x string) bool) {
		defer file.Close()

		s := bufio.NewScanner(file)
		for s.Scan() {
			hostname, _, _ := strings.Cut(s.Text(), "#")

			if hostname == "" {
				continue
			}

			if !f(hostname) {
				break
			}
		}
	}
}

func RangeSelectByMap[S ~[]T, T comparable, T2 any](Ss S, m map[T]T2) func(f func(T, T2) bool) {
	return func(f2 func(T, T2) bool) {
		for _, v := range Ss {
			v2, ok := m[v]
			if !ok {
				continue
			}

			if !f2(v, v2) {
				return
			}
		}
	}
}

type SelectVaule[T, T1, T2 any] struct {
	Key T
	V1  T1
	V2  T2
}

func RangeIterSelectByMap[T comparable, T2 any, T3 any](iter iter.Seq2[T, T3], m map[T]T2) func(f func(SelectVaule[T, T2, T3]) bool) {
	return func(f2 func(SelectVaule[T, T2, T3]) bool) {
		for k, v := range iter {
			v2, ok := m[k]
			if !ok {
				continue
			}

			if !f2(SelectVaule[T, T2, T3]{
				Key: k,
				V1:  v2,
				V2:  v,
			}) {
				return
			}
		}
	}
}
