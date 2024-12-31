package simplehttp

import (
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestServer(t *testing.T) {
	mux := http.NewServeMux()

	mux.Handle("GET /hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))

	HandleFront(mux)

	lis, err := net.Listen("tcp", "0.0.0.0:8089")
	assert.NoError(t, err)

	http.Serve(lis, mux)
}
