package httpserver

import (
	"testing"
	"time"
)

func TestNewHTTPServer(t *testing.T) {
	_, err := NewHTTPServer("127.0.0.1", "8788", "", "")
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Hour)
}
