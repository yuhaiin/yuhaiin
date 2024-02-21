package tun

import (
	"fmt"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/utils/net"
)

type TunScheme struct {
	Fd     int
	Scheme string
	Name   string
}

func ParseTunScheme(str string) (TunScheme, error) {
	scheme, name, err := net.GetScheme(str)
	if err != nil {
		return TunScheme{}, err
	}

	if len(name) < 3 {
		return TunScheme{}, fmt.Errorf("invalid tun name: %s", name)
	}

	name = name[2:]

	var fd int
	switch scheme {
	case "tun":
	case "fd":
		fd, err = strconv.Atoi(name)
		if err != nil {
			return TunScheme{}, fmt.Errorf("invalid fd: %s", name)
		}
	default:
		return TunScheme{}, fmt.Errorf("invalid tun name: %s", str)
	}

	return TunScheme{
		Scheme: scheme,
		Name:   name,
		Fd:     fd,
	}, nil
}
