package api

import (
	"flag"
	fmt "fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/app"
)

type manager struct {
	host    string
	killWDC bool // kill process when grpc disconnect

	lock     bool
	init     bool
	conn     chan bool
	entrance *app.Entrance
}

func newManager(e *app.Entrance) *manager {
	return &manager{
		conn:     make(chan bool),
		entrance: e,
	}
}

func (m *manager) lockfile() bool {
	return m.lock
}

func (m *manager) initApp() bool {
	return m.init
}

func (m *manager) Host() string {
	return m.host
}
func (m *manager) connect() {
	close(m.conn)
}

func sigh() {
	go func() {
		signChannel := make(chan os.Signal, 5)
		signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Println("kernel exit")
				_ = app.LockFileClose()
				os.Exit(0)
			default:
				fmt.Println("OTHERS SIGN:", s)
			}
		}
	}()
}

func (m *manager) Start() error {
	sigh()

	flag.StringVar(&m.host, "host", "127.0.0.1:50051", "RPC SERVER HOST")
	flag.BoolVar(&m.killWDC, "kwdc", false, "kill process when grpc disconnect")
	flag.Parse()
	fmt.Println("gRPC Listen Host :", m.host)
	fmt.Println("Try to create lock file.")

	err := app.GetProcessLock(m.host)
	if err != nil {
		fmt.Println("Create lock file failed, Please Get Running Host in 5 Seconds.")
		go func() {
			time.Sleep(8 * time.Second)
			os.Exit(0)
		}()
		return nil
	}
	m.lock = true

	fmt.Println("Create lock file successful.")
	fmt.Println("Try to initialize Service.")

	err = m.entrance.Start()
	if err != nil {
		fmt.Println("Initialize Service failed, Exit Process!")
		return err
	}
	m.init = true
	fmt.Println("Initialize Service Successful, Please Connect in 5 Seconds.")

	go func() {
		select {
		case <-m.conn:
			fmt.Println("Connect Successful!")
		case <-time.After(5 * time.Second):
			log.Println("Connect timeout: 5 Seconds, Exit Process!")
			close(m.conn)
			os.Exit(0)
		}
	}()
	return nil
}
