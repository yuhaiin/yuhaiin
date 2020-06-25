// +build !noGui

package main

import (
	"log"

	process2 "github.com/Asutorufa/yuhaiin/process/process"

	"github.com/Asutorufa/yuhaiin/config"

	//_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/gui"
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
	if err := config.PathInit(); err != nil {
		gui.MessageBox(err.Error())
		return
	}
	if err := process2.GetProcessLock(); err != nil {
		gui.MessageBox("Process is already running!\nError Message: " + err.Error())
		return
	}
	defer process2.LockFileClose()

	gui.NewGui().App.Exec()
}
