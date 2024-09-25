package slice

import (
	"bufio"
	"io"
	"iter"
	"os"
	"strings"
)

type ToFunc[T, T2 any] func(T) T2

func To[T, T2 any](from []T, f ToFunc[T, T2]) []T2 {
	to := make([]T2, len(from))
	for i, v := range from {
		to[i] = f(v)
	}

	return to
}

func CollectTo[T, T2 any](iter iter.Seq[T], f ToFunc[T, T2]) []T2 {
	to := make([]T2, 0)
	for v := range iter {
		to = append(to, f(v))
	}
	return to
}

func RangeFileByLine(path string) iter.Seq[string] {
	return func(f func(x string) bool) {
		file, err := os.OpenFile(path, os.O_RDONLY, 0)
		if err != nil {
			return
		}

		RangeReaderByLine(file)(f)
	}
}

func RangeReaderByLine(reader io.ReadCloser) iter.Seq[string] {
	return func(f func(x string) bool) {
		defer reader.Close()

		s := bufio.NewScanner(reader)
		for s.Scan() {
			hostname := s.Text()

			if i := strings.IndexByte(hostname, '#'); i > 0 {
				hostname = hostname[:i]
			}

			if hostname == "" {
				continue
			}

			if !f(hostname) {
				break
			}
		}
	}
}

func RangeSelectByMap[S ~[]T, T comparable, T2 any](Ss S, m map[T]T2) iter.Seq2[T, T2] {
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

func RangeIterSelectByMap[T comparable, T2 any, T3 any](iter iter.Seq2[T, T3], m map[T]T2) iter.Seq[SelectVaule[T, T2, T3]] {
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
