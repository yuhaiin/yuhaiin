package api

import (
	context "context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Process struct {
	UnimplementedProcessInitServer

	singleInstance chan bool
	message        chan string
	manager        *app.Manager
}

func NewProcess(e *app.Manager) *Process {
	return &Process{
		manager: e,
	}
}

func (s *Process) CreateLockFile(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	if !s.manager.Lockfile() {
		return &emptypb.Empty{}, errors.New("create lock file false")
	}

	if !s.manager.InitApp() {
		return &emptypb.Empty{}, errors.New("init Process Failed")
	}

	s.manager.Connect()
	return &emptypb.Empty{}, nil
}

func (s *Process) ProcessInit(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *Process) GetRunningHost(context.Context, *emptypb.Empty) (*wrapperspb.StringValue, error) {
	host, err := app.ReadLockFile()
	if err != nil {
		return &wrapperspb.StringValue{}, err
	}
	return &wrapperspb.StringValue{Value: host}, nil
}

func (s *Process) ClientOn(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	if s.singleInstance != nil {
		select {
		case <-s.singleInstance:
			break
		default:
			s.message <- "on"
			return &emptypb.Empty{}, nil
		}
	}
	return &emptypb.Empty{}, errors.New("no client")
}

func (s *Process) ProcessExit(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, app.LockFileClose()
}

func (s *Process) SingleInstance(srv ProcessInit_SingleInstanceServer) error {
	if s.singleInstance != nil {
		select {
		case <-s.singleInstance:
			break
		default:
			return errors.New("already exist one client")
		}
	}

	s.singleInstance = make(chan bool)
	s.message = make(chan string, 1)
	ctx := srv.Context()

	for {
		select {
		case m := <-s.message:
			err := srv.Send(&wrapperspb.StringValue{Value: m})
			if err != nil {
				log.Println(err)
			}
			fmt.Println("Call Client Open Window.")
		case <-ctx.Done():
			close(s.message)
			close(s.singleInstance)
			if s.manager.KillWDC() {
				panic("client exit")
			}
			return ctx.Err()
		}
	}
}

func (s *Process) GetKernelPid(context.Context, *emptypb.Empty) (*wrapperspb.UInt32Value, error) {
	return &wrapperspb.UInt32Value{Value: uint32(os.Getpid())}, nil
}

func (s *Process) StopKernel(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	defer os.Exit(0)
	return &emptypb.Empty{}, nil
}
