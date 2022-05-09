package config

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func DefaultConfigDir() (Path string) {
	var err error
	Path, err = os.UserConfigDir()
	if err == nil {
		Path = filepath.Join(Path, "yuhaiin")
		return
	}

	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		log.Println(err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}
	execPath, err := filepath.Abs(file)
	if err != nil {
		log.Println(err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}

	Path = filepath.Join(filepath.Dir(execPath), "config")
	return
}

var execProtocol syncmap.SyncMap[reflect.Type, func(isServerProtocol_Protocol, proxy.Proxy) (server.Server, error)]

func RegisterProtocol[T isServerProtocol_Protocol](wrap func(T, proxy.Proxy) (server.Server, error)) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(t isServerProtocol_Protocol, p proxy.Proxy) (server.Server, error) {
			return wrap(t.(T), p)
		},
	)
}

func CreateServer(p isServerProtocol_Protocol, dialer proxy.Proxy) (server.Server, error) {
	conn, ok := execProtocol.Load(reflect.TypeOf(p))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", p)
	}

	return conn(p, dialer)
}
