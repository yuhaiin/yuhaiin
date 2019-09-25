// +build !noGui

package main

import (
	"flag"
	"log"
	"os"

	"./gui"
	"./init"
	"./net"
	"./process"
	"./process/lockfile"
)

func main() {
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
