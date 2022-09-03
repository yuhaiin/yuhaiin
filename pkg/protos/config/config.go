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

var execProtocol syncmap.SyncMap[reflect.Type, func(*Opts[IsServerProtocol_Protocol]) (server.Server, error)]

func RegisterProtocol[T isServerProtocol_Protocol](wrap func(*Opts[T]) (server.Server, error)) {
	if wrap == nil {
		return
	}

	var z T
	execProtocol.Store(
		reflect.TypeOf(z),
		func(p *Opts[IsServerProtocol_Protocol]) (server.Server, error) {
			return wrap(CovertOpts(p, func(p IsServerProtocol_Protocol) T { return p.(T) }))
		},
	)
}

type UidDumper interface {
	DumpUid(ipProto int32, srcIp string, srcPort int32, destIp string, destPort int32) (int32, error)
	GetUidInfo(uid int32) (string, error)
}

type Opts[T isServerProtocol_Protocol] struct {
	Dialer    proxy.Proxy
	DNSServer server.DNSServer
	UidDumper UidDumper
	IPv6      bool

	Protocol T
}

type IsServerProtocol_Protocol interface {
	isServerProtocol_Protocol
}

func CovertOpts[T1, T2 isServerProtocol_Protocol](o *Opts[T1], f func(t T1) T2) *Opts[T2] {
	return &Opts[T2]{
		Dialer:    o.Dialer,
		DNSServer: o.DNSServer,
		UidDumper: o.UidDumper,
		IPv6:      o.IPv6,
		Protocol:  f(o.Protocol),
	}
}

func CreateServer(opts *Opts[IsServerProtocol_Protocol]) (server.Server, error) {
	conn, ok := execProtocol.Load(reflect.TypeOf(opts.Protocol))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", opts.Protocol)
	}
	return conn(opts)
}
