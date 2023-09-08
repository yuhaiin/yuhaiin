package main

import (
	"net/http"
	"path/filepath"
	"strings"
)

func main() {
	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("/home/asutorufa/Documents/Programming/yuhaiin-react/out"))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/docs") {
			if ext := filepath.Ext(r.URL.Path); ext == "" {
				r.URL.Path = r.URL.Path + ".html"
			}
		}
		fs.ServeHTTP(w, r)
	})

	if err := http.ListenAndServe(":8001", mux); err != nil {
		panic(err)
	}

}
