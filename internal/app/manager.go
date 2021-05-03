package app

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type Manager struct {
	lock    bool
	init    bool
	conn    chan bool
	applock *Lock
}

func NewManager(configPath string) *Manager {
	return &Manager{
		conn:    make(chan bool),
		applock: NewLock(filepath.Join(configPath, "yuhaiin.lock")),
	}
}

func (m *Manager) Lockfile() bool {
	return m.lock
}

func (m *Manager) InitApp() bool {
	return m.init
}

func (m *Manager) ReadHost() (string, error) {
	return m.applock.Payload()
}

func (m *Manager) Close() error {
	return m.applock.UnLock()
}

func (m *Manager) Connect() {
	close(m.conn)
}

func (m *Manager) sigh() {
	go func() {
		signChannel := make(chan os.Signal, 5)
		signal.Notify(signChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		for s := range signChannel {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Println("kernel exit")
				_ = m.applock.UnLock()
				os.Exit(0)
			default:
				fmt.Println("OTHERS SIGN:", s)
			}
		}
	}()
}

func (m *Manager) Start(host string, errs error) error {
	m.sigh()

	err := m.applock.Lock(host)
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

	if errs != nil {
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
