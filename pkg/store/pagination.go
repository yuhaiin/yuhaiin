package store

import "strings"

func normalizeStorePage(page, pageSize int) (int, int, int) {
	page = max(page, 1)
	pageSize = max(pageSize, 0)
	return page, pageSize, (page - 1) * pageSize
}

func appendStorePage(query string, args []any, page, pageSize int) (string, []any) {
	if pageSize <= 0 {
		return query, args
	}
	_, _, offset := normalizeStorePage(page, pageSize)
	return query + " LIMIT ? OFFSET ?", append(args, pageSize, offset)
}

func normalizedStoreQuery(query string) string {
	return strings.ToLower(strings.TrimSpace(query))
}

func storeLike(query string) string {
	return "%" + normalizedStoreQuery(query) + "%"
}
