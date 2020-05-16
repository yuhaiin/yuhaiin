// +build !noGui

package main

import (
	"log"
	//_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/gui"
	"github.com/Asutorufa/yuhaiin/process"
)

func main() {
	//go func() {
	//	// 开启pprof，监听请求
	//	ip := "0.0.0.0:6060"
	//	if err := http.ListenAndServe(ip, nil); err != nil {
	//		fmt.Printf("start pprof failed on %s\n", ip)
	//	}
	//}()
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	if err := process.GetProcessLock(); err != nil {
		log.Println("Process is already running!\nError Message: " + err.Error())
		return
	}
	defer process.LockFileClose()

	ssrMicroClientGUI, err := gui.NewGui()
	if err != nil {
		log.Println(err)
	}
	if ssrMicroClientGUI != nil {
		//ssrMicroClientGUI.MainWindow.Show()
		ssrMicroClientGUI.App.Exec()
	} else {
		log.Println(err)
	}
}
