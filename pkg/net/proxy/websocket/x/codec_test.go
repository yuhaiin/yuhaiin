package websocket

import (
	"errors"
	"net"
	"testing"
)

func TestJSONReceiveUsesReader(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := newConn(clientRaw, false)
	server := newConn(serverRaw, true)

	payload := []byte(`{"message":"hello","count":42}`)
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.WriteMsg(payload, OpText)
		writeErr <- err
	}()

	codec := JSON
	codec.Unmarshal = func([]byte, opcode, any) error {
		return errors.New("buffered unmarshal path used")
	}

	var got struct {
		Message string `json:"message"`
		Count   int    `json:"count"`
	}
	if err := codec.Receive(server, &got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	if got.Message != "hello" || got.Count != 42 {
		t.Fatalf("unexpected decoded value: %+v", got)
	}
}
