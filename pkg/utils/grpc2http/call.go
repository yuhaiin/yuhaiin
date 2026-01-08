package grpc2http

import (
	"fmt"
	"io"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func Call(srv any, handler grpc.MethodHandler) func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var data []byte
		var err error
		if r.ContentLength > 0 && r.ContentLength <= pool.MaxSegmentSize {
			data = pool.GetBytes(r.ContentLength)
			defer pool.PutBytes(data)
			_, err = io.ReadFull(r.Body, data)
		} else {
			data, err = io.ReadAll(r.Body)
		}
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		dec := func(a any) error {
			z, ok := a.(proto.Message)
			if !ok {
				return fmt.Errorf("not proto message")
			}

			return proto.Unmarshal(data, z)
		}

		resp, err := handler(srv, r.Context(), dec, nil)
		if err != nil {
			return fmt.Errorf("handler failed: %w", err)
		}

		res, ok := resp.(proto.Message)
		if !ok {
			return fmt.Errorf("resp not proto message")
		}

		data, err = marshalWithPool(res)
		if err != nil {
			return fmt.Errorf("marshal failed: %w", err)
		}
		defer pool.PutBytes(data)

		w.Header().Set("Content-Type", "application/protobuf")
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("write failed: %w", err)
		}

		return nil
	}
}

func marshalWithPool(m proto.Message) ([]byte, error) {
	marshal := proto.MarshalOptions{
		Deterministic: true,
	}

	size := marshal.Size(m)

	if size == 0 {
		return []byte{}, nil
	}

	buf := pool.GetBytes(size)

	data, err := marshal.MarshalAppend(buf[:0], m)
	if err != nil {
		pool.PutBytes(buf)
		return nil, err
	}

	return data, nil
}
