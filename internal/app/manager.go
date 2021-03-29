package app

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Manager struct {
	host    string
	killWDC bool // kill process when grpc disconnect

	lock     bool
	init     bool
	conn     chan bool
	entrance *Entrance
}

func NewManager() (*Manager, error) {
	m := &Manager{
		conn: make(chan bool),
	}
	var err error
	m.entrance, err = NewEntrance()
	return m, err
}

func (m *Manager) Lockfile() bool {
	return m.lock
}

func (m *Manager) InitApp() bool {
	return m.init
}

func (m *Manager) KillWDC() bool {
	return m.killWDC
}

func (m *Manager) Entrance() *Entrance {
	return m.entrance
}

func (m *Manager) Host() string {
	return m.host
}
func (m *Manager) Connect() {
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
				_ = LockFileClose()
				os.Exit(0)
			default:
				fmt.Println("OTHERS SIGN:", s)
			}
		}
	}()
}

func (m *Manager) Start() error {
	sigh()

	flag.StringVar(&m.host, "host", "127.0.0.1:50051", "RPC SERVER HOST")
	flag.BoolVar(&m.killWDC, "kwdc", false, "kill process when grpc disconnect")
	flag.Parse()
	fmt.Println("gRPC Listen Host :", m.host)
	fmt.Println("Try to create lock file.")

	err := GetProcessLock(m.host)
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
	fmt.Println("Initialize Service Successful, Please Connect in 30 Seconds.")

	go func() {
		select {
		case <-m.conn:
			fmt.Println("Connect Successful!")
		case <-time.After(30 * time.Second):
			log.Println("Connect timeout: 30 Seconds, Exit Process!")
			close(m.conn)
			os.Exit(0)
		}
	}()
	return nil
}
