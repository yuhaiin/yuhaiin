package slice

import (
	"bufio"
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

func RangeFileByLine(path string, f func(x string)) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer file.Close()

	s := bufio.NewScanner(file)

	for s.Scan() {
		hostname, _, _ := strings.Cut(s.Text(), "#")

		if hostname == "" {
			continue
		}

		f(hostname)
	}
}
