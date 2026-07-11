package paging

import "strings"

const (
	DefaultPageSize uint32 = 8
	MaxPageSize     uint32 = 100
)

func Normalize(page, pageSize uint32) (uint32, uint32) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return page, pageSize
}

func Slice[T any](items []T, page, pageSize uint32) ([]T, uint32, uint32, uint32) {
	page, pageSize = Normalize(page, pageSize)
	total := uint32(len(items))
	start := (page - 1) * pageSize
	if start >= total {
		return nil, page, pageSize, total
	}
	end := min(start+pageSize, total)
	return items[start:end], page, pageSize, total
}

func Filter[T any](items []T, query string, match func(T, string) bool) []T {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return items
	}

	filtered := make([]T, 0, len(items))
	for _, item := range items {
		if match(item, query) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func MatchString(value, query string) bool {
	return strings.Contains(strings.ToLower(value), query)
}
