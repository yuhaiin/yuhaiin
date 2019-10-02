// +build !noGui

package main

import (
	"flag"
	"log"
	"os"

	"./gui"
	ssrinit "./init"
	getdelay "./net"
	"./process"
	"./process/lockfile"
)

func main() {
	// windows
	// modkernel32 := syscall.NewLazyDLL("kernel32.dll")
	// procAllocConsole := modkernel32.NewProc("AllocConsole")
	// r0, _, err0 := syscall.Syscall(procAllocConsole.Addr(), 0, 0, 0, 0)
	// if r0 == 0 {
	// 	fmt.Printf("Could not allocate console: %s. Check build flags..", err0)
	// 	os.Exit(1)
	// }
	// hout, err1 := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	// if err1 != nil {
	// 	os.Exit(2)
	// }
	// os.Stdout = os.NewFile(uintptr(hout), "/dev/stdout")

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	configPath := ssrinit.GetConfigAndSQLPath()
	daemon := flag.String("d", "", "d")
	subDaemon := flag.String("sd", "", "sd")
	flag.Parse()

	if *daemon != "" {
		process.Start(configPath)
	}
	if *subDaemon != "" {
		if *subDaemon == "ssr" {
			process.Start(configPath)
		} else if *subDaemon == "http" {
			getdelay.StartHTTP(configPath)
		} else if *subDaemon == "httpBp" {
			getdelay.StartHTTPBypass(configPath)
		} else if *subDaemon == "httpB" {
			getdelay.StartHTTPByArgument()
		} else if *subDaemon == "socks5Bp" {
			getdelay.StartSocks5Bypass(configPath)
		} else if *subDaemon == "httpBBp" {
			getdelay.StartHTTPByArgumentBypass()
		}
	} else {
		ssrMicroClientGUI, err := gui.NewSsrMicroClientGUI(configPath)
		if err != nil && ssrMicroClientGUI != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}

		lockFile, err := os.Create(configPath +
			"/SsrMicroClientRunStatuesLockFile")
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}

		if err = lockfile.LockFile(lockFile); err != nil {
			ssrMicroClientGUI.MessageBox("process is exist!\n" + err.Error())
			return
		} else {
			defer lockFile.Close()
			defer os.Remove(configPath + "/SsrMicroClientRunStatuesLockFile")
		}
		ssrMicroClientGUI.BeforeShow()
		ssrMicroClientGUI.MainWindow.Show()
		ssrMicroClientGUI.App.Exec()
	}
}
