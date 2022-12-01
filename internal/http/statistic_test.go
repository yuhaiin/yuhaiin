package simplehttp

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/websocket"
)

func TestWebsocket(t *testing.T) {
	ws, err := websocket.Dial("ws://localhost:50051/conn", "", "localhost:50051")
	assert.NoError(t, err)

	ws.Write(nil)

	var z string
	websocket.Message.Receive(ws, &z)
	t.Log(z)
}
