// +build !noGui

package main

import (
	"log"

	"github.com/Asutorufa/yuhaiin/config"

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

	//messageBox := func(text string) {
	//widgets.NewQApplication(len(os.Args), os.Args)
	//message := widgets.NewQMessageBox(nil)
	//message.SetText(text)
	//message.Exec()
	//}
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	if err := config.PathInit(); err != nil {
		gui.MessageBox(err.Error())
		return
	}
	if err := process.GetProcessLock(); err != nil {
		gui.MessageBox("Process is already running!\nError Message: " + err.Error())
		return
	}
	defer process.LockFileClose()

	gui.NewGui().App.Exec()
}
