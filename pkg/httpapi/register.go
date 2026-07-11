package httpapi

import "net/http"

// RegisterFunc is the small adapter used by RegisterV2 to attach handlers to
// the host application's ServeMux.
type RegisterFunc func(pattern string, handler func(http.ResponseWriter, *http.Request) error)
