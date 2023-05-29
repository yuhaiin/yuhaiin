package slice

func To[T, T2 any](from []T, f func(T) T2) []T2 {
	to := make([]T2, len(from))
	for i, v := range from {
		to[i] = f(v)
	}

	return to
}
