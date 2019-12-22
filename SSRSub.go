// +build !noGui

package main

import (
	ssrinit "SsrMicroClient/init"
	"SsrMicroClient/process"
	"flag"
	"log"
	"os"

	"SsrMicroClient/gui"
	"SsrMicroClient/process/lockfile"
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
		}
		//else if *subDaemon == "http" {
		//	test.StartHTTP(configPath)
		//} else if *subDaemon == "httpBp" {
		//	test.StartHTTPBypass(configPath)
		//} else if *subDaemon == "httpB" {
		//	test.StartHTTPByArgument()
		//} else if *subDaemon == "socks5Bp" {
		//	test.StartSocks5Bypass(configPath)
		//} else if *subDaemon == "httpBBp" {
		//	test.StartHTTPByArgumentBypass()
		//}
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
		}
		defer func() {
			_ = lockFile.Close()
			_ = os.Remove(configPath + "/SsrMicroClientRunStatuesLockFile")
		}()

		if ssrMicroClientGUI.App.IsSessionRestored() {
			ssrMicroClientGUI.MessageBox("restore is from before")
		}

		ssrMicroClientGUI.BeforeShow()
		//ssrMicroClientGUI.MainWindow.Show()
		ssrMicroClientGUI.App.Exec()
	}
}
