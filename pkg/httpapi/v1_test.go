package httpapi

import (
	"net/http"
	"testing"
)

func TestRegisterV1PatternsAreServeMuxCompatible(t *testing.T) {
	mux := http.NewServeMux()
	RegisterV1(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			_ = handler(w, r)
		})
	}, Services{})
}
