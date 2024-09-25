package tools

import (
	"context"
	"net"

	"google.golang.org/protobuf/types/known/emptypb"
)

type Tools struct {
	UnimplementedToolsServer
}

func NewTools() *Tools {
	return &Tools{}
}

func (t *Tools) GetInterface(context.Context, *emptypb.Empty) (*Interfaces, error) {
	is := &Interfaces{}
	iis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range iis {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		iif := &Interface{
			Name: i.Name,
		}

		addresses, err := i.Addrs()
		if err == nil {
			for _, a := range addresses {
				iif.Addresses = append(iif.Addresses, a.String())
			}
		}
		is.Interfaces = append(is.Interfaces, iif)
	}

	return is, nil
}
