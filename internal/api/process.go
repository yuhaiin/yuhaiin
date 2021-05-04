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

var _ ProcessInitServer = (*Process)(nil)

type Process struct {
	UnimplementedProcessInitServer
	singleInstance chan bool
	message        chan string

	locks *app.Lock
	host  string
}

func NewProcess(lock *app.Lock, host string) ProcessInitServer {
	return &Process{locks: lock, host: host}
}

func (s *Process) CreateLockFile(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	if s.locks.Lock(s.host) != nil {
		return &emptypb.Empty{}, errors.New("create lock file false")
	}
	return &emptypb.Empty{}, nil
}

func (s *Process) ProcessInit(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *Process) GetRunningHost(context.Context, *emptypb.Empty) (*wrapperspb.StringValue, error) {
	host, err := s.locks.Payload()
	if err != nil {
		return &wrapperspb.StringValue{}, fmt.Errorf("get payload failed: %v", err)
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
	return &emptypb.Empty{}, nil
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
