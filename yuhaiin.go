// +build !noGui

package main

import (
	"log"
	"os"

	//_ "net/http/pprof"

	"github.com/Asutorufa/yuhaiin/gui"
	"github.com/Asutorufa/yuhaiin/process"
	"github.com/therecipe/qt/widgets"
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
		widgets.NewQApplication(len(os.Args), os.Args)
		message := widgets.NewQMessageBox(nil)
		message.SetText("Process is already running!\nError Message: " + err.Error())
		message.Exec()
		return
	}
	defer process.LockFileClose()

	gui.NewGui().App.Exec()
}
