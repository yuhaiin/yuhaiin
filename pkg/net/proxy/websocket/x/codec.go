package websocket

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultMaxPayloadBytes = 32 << 20 // 32MB
)

// Codec represents a symmetric pair of functions that implement a codec.
type Codec struct {
	Marshal   func(v any) (data []byte, payloadType opcode, err error)
	Unmarshal func(data []byte, payloadType opcode, v any) (err error)
}

// Send sends v marshaled by cd.Marshal as single frame to ws.
func (cd Codec) Send(ws *Conn, v any) (err error) {
	data, payloadType, err := cd.Marshal(v)
	if err != nil {
		return err
	}
	_, err = ws.WriteMsg(data, payloadType)
	return err
}

// Receive receives single frame from ws, unmarshaled by cd.Unmarshal and stores
// in v. The whole frame payload is read to an in-memory buffer; max size of
// payload is defined by ws.MaxPayloadBytes. If frame payload size exceeds
// limit, ErrFrameTooLarge is returned; in this case frame is not read off wire
// completely. The next call to Receive would read and discard leftover data of
// previous oversized frame before processing next frame.
func (cd Codec) Receive(ws *Conn, v any) error {
	return ws.NextFrameReader(func(header *Header, frame io.ReadCloser) error {
		if header.payloadLength > int64(DefaultMaxPayloadBytes) {
			// payload size exceeds limit, no need to call Unmarshal
			//
			// set frameReader to current oversized frame so that
			// the next call to this function can drain leftover
			// data before processing the next frame
			ws.Frame = frame
			return errors.New("websocket: frame payload size exceeds limit")
		}

		data, err := io.ReadAll(frame)
		if err != nil {
			return err
		}
		return cd.Unmarshal(data, header.opcode, v)
	})

}

func marshal(v any) (msg []byte, _ opcode, err error) {
	switch data := v.(type) {
	case string:
		return []byte(data), opText, nil
	case []byte:
		return data, opBinary, nil
	}
	return nil, 8, ErrNotSupported
}

func unmarshal(msg []byte, _ opcode, v any) (err error) {
	switch data := v.(type) {
	case *string:
		*data = string(msg)
		return nil
	case *[]byte:
		*data = msg
		return nil
	}
	return ErrNotSupported
}

/*
Message is a codec to send/receive text/binary data in a frame on WebSocket connection.
To send/receive text frame, use string type.
To send/receive binary frame, use []byte type.

Trivial usage:

	import "websocket"

	// receive text frame
	var message string
	websocket.Message.Receive(ws, &message)

	// send text frame
	message = "hello"
	websocket.Message.Send(ws, message)

	// receive binary frame
	var data []byte
	websocket.Message.Receive(ws, &data)

	// send binary frame
	data = []byte{0, 1, 2}
	websocket.Message.Send(ws, data)
*/
var Message = Codec{marshal, unmarshal}

func jsonMarshal(v any) (msg []byte, payloadType opcode, err error) {
	msg, err = json.Marshal(v)
	return msg, opText, err
}

func jsonUnmarshal(msg []byte, payloadType opcode, v any) (err error) {
	return json.Unmarshal(msg, v)
}

/*
JSON is a codec to send/receive JSON data in a frame from a WebSocket connection.

Trivial usage:

	import "websocket"

	type T struct {
		Msg string
		Count int
	}

	// receive JSON type T
	var data T
	websocket.JSON.Receive(ws, &data)

	// send JSON type T
	websocket.JSON.Send(ws, data)
*/
var JSON = Codec{jsonMarshal, jsonUnmarshal}

func protoMarshal(v any) (msg []byte, payloadType opcode, err error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, 0, fmt.Errorf("data is not proto message")
	}

	msg, err = proto.Marshal(m)
	return msg, opBinary, err
}

func protoUnmarshal(msg []byte, payloadType opcode, v any) (err error) {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("data is not proto message")
	}

	return proto.Unmarshal(msg, m)
}

var PROTO = Codec{protoMarshal, protoUnmarshal}

func protoJsonMarshal(v any) (msg []byte, payloadType opcode, err error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, 0, fmt.Errorf("data is not proto message")
	}

	msg, err = protojson.Marshal(m)
	return msg, opBinary, err
}

func protoJsonUnmarshal(msg []byte, payloadType opcode, v any) (err error) {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("data is not proto message")
	}

	return protojson.Unmarshal(msg, m)
}

var PROTOJSON = Codec{protoJsonMarshal, protoJsonUnmarshal}
