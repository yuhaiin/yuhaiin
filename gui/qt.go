package main

import (
	"../config/configJson"
	"../init"
	"../net"
	"../process"
	"flag"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
	"log"
	"os"
)

func SSRSub(configPath string) {

	window := widgets.NewQMainWindow(nil, 0)
	//window.SetMinimumSize2(600, 400)
	window.SetFixedSize2(600, 400)
	window.SetWindowTitle("SsrMicroClient")
	window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		closeMessageBox := widgets.NewQMessageBox(window)
		closeMessageBox.SetWindowTitle("close?")
		closeMessageBox.SetText("which are you want to do?")
		closeMessageBox.SetStandardButtons(0x00100000 | 0x00004000 | 0x00000400 | 0x00400000)
		closeMessageBox.Button(0x00004000).SetText("exit(ssr daemon)")
		closeMessageBox.Button(0x00000400).SetText("exit")
		closeMessageBox.Button(0x00100000).SetText("run in background")
		closeMessageBox.SetDefaultButton2(0x00100000)
		if exec := closeMessageBox.Exec(); exec == 0x00004000 {
			os.Exit(0)
		} else if exec == 0x00000400 {
		} else if exec == 0x00100000 {
			window.Hide()
		}
	})

	subWindow := subUI(configPath, window)

	trayIcon := widgets.NewQSystemTrayIcon(window)
	trayIcon.ConnectMessageClicked(func() {
		log.Println("sss")
	})
	icon := gui.NewQIcon5("/mnt/share/code/golang/SsrMicroClient/SSRSub.png")
	trayIcon.SetIcon(icon)
	menu := widgets.NewQMenu(window)
	ssrMicroClientTrayIconMenu := widgets.NewQAction2("SsrMicroClient", window)
	ssrMicroClientTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		if window.IsHidden() == false {
			window.Hide()
		}
		window.Show()
	})
	subscriptionTrayIconMenu := widgets.NewQAction2("subscription", window)
	subscriptionTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		if subWindow.IsHidden() == false {
			subWindow.Close()
		}
		subWindow.Show()
	})
	exit := widgets.NewQAction2("exit", window)
	exit.ConnectTriggered(func(bool2 bool) { os.Exit(0) })
	actions := []*widgets.QAction{ssrMicroClientTrayIconMenu, subscriptionTrayIconMenu, exit}
	menu.AddActions(actions)
	trayIcon.SetContextMenu(menu)
	trayIcon.Show()

	statusLabel := widgets.NewQLabel2("status", window, core.Qt__WindowType(0x00000000))
	statusLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 10), core.NewQPoint2(130, 40)))
	var status string
	if pid, run := process.Get(configPath); run == true {
		status = "<b><font color=green>running (pid: " + pid + ")</font></b>"
	} else {
		status = "<b><font color=reb>stopped</font></b>"
	}
	statusLabel2 := widgets.NewQLabel2(status, window, core.Qt__WindowType(0x00000000))
	statusLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 10), core.NewQPoint2(560, 40)))

	nowNodeLabel := widgets.NewQLabel2("now node", window, core.Qt__WindowType(0x00000000))
	nowNodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 60), core.NewQPoint2(130, 90)))
	nowNode, err := configJSON.GetNowNode(configPath)
	if err != nil {
		log.Println(err)
		return
	}
	nowNodeLabel2 := widgets.NewQLabel2(nowNode["remarks"]+" - "+nowNode["group"], window, core.Qt__WindowType(0x00000000))
	nowNodeLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 60), core.NewQPoint2(560, 90)))

	groupLabel := widgets.NewQLabel2("group", window, core.Qt__WindowType(0x00000000))
	groupLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 110), core.NewQPoint2(130, 140)))
	groupCombobox := widgets.NewQComboBox(window)
	group, err := configJSON.GetGroup(configPath)
	if err != nil {
		log.Println(err)
		return
	}
	groupCombobox.AddItems(group)
	groupCombobox.SetCurrentTextDefault(nowNode["group"])
	groupCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 110), core.NewQPoint2(450, 140)))
	refreshButton := widgets.NewQPushButton2("refresh", window)
	refreshButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 110), core.NewQPoint2(560, 140)))

	nodeLabel := widgets.NewQLabel2("node", window, core.Qt__WindowType(0x00000000))
	nodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 160), core.NewQPoint2(130, 190)))
	nodeCombobox := widgets.NewQComboBox(window)
	node, err := configJSON.GetNode(configPath, groupCombobox.CurrentText())
	if err != nil {
		log.Println(err)
		return
	}
	nodeCombobox.AddItems(node)
	nodeCombobox.SetCurrentTextDefault(nowNode["remarks"])
	nodeCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 160), core.NewQPoint2(450, 190)))
	startButton := widgets.NewQPushButton2("start", window)
	startButton.ConnectClicked(func(bool2 bool) {
		group := groupCombobox.CurrentText()
		remarks := nodeCombobox.CurrentText()
		_, exist := process.Get(configPath)
		if group == nowNode["group"] && remarks == nowNode["remarks"] && exist == true {
			return
		} else if group == nowNode["group"] && remarks == nowNode["remarks"] && exist == false {
			process.StartByArgument(configPath, "ssr")
			var status string
			if pid, run := process.Get(configPath); run == true {
				status = "<b><font color=green>running (pid: " + pid + ")</font></b>"
			} else {
				status = "<b><font color=reb>stopped</font></b>"
			}
			statusLabel2.SetText(status)
		} else {
			err := configJSON.ChangeNowNode2(configPath, group, remarks)
			if err != nil {
				return
			}
			nowNode, err = configJSON.GetNowNode(configPath)
			if err != nil {
				log.Println(err)
				return
			}
			nowNodeLabel2.SetText(nowNode["remarks"] + " - " + nowNode["group"])
			if exist == true {
				process.Stop(configPath)
				// ssr_process.Start(path, db_path)
				process.StartByArgument(configPath, "ssr")
			} else {
				process.StartByArgument(configPath, "ssr")
			}
			var status string
			if pid, run := process.Get(configPath); run == true {
				status = "<b><font color=green>running (pid: " + pid + ")</font></b>"
			} else {
				status = "<b><font color=reb>stopped</font></b>"
			}
			statusLabel2.SetText(status)
		}
	})
	startButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 160), core.NewQPoint2(560, 190)))

	delayLabel := widgets.NewQLabel2("delay", window, core.Qt__WindowType(0x00000000))
	delayLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 210), core.NewQPoint2(130, 240)))
	delayLabel2 := widgets.NewQLabel2("", window, core.Qt__WindowType(0x00000000))
	delayLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 210), core.NewQPoint2(450, 240)))
	delayButton := widgets.NewQPushButton2("get delay", window)
	delayButton.ConnectClicked(func(bool2 bool) {
		group := groupCombobox.CurrentText()
		remarks := nodeCombobox.CurrentText()
		node, err := configJSON.GetOneNode(configPath, group, remarks)
		if err != nil {
			log.Println(err)
			return
		}
		delay, isSuccess, _ := getdelay.TCPDelay(node.Server, node.ServerPort)
		delayString := delay.String()
		if isSuccess == false {
			delayString = "delay > 5s or cannot connect"
		}
		delayLabel2.SetText(delayString)
	})
	delayButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 210), core.NewQPoint2(560, 240)))

	groupCombobox.ConnectCurrentTextChanged(func(string2 string) {
		node, err := configJSON.GetNode(configPath, groupCombobox.CurrentText())
		if err != nil {
			log.Println(err)
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)
	})

	subButton := widgets.NewQPushButton2("subscription setting", window)
	subButton.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 260), core.NewQPoint2(290, 290)))
	subButton.ConnectClicked(func(bool2 bool) {
		if subWindow.IsHidden() == false {
			subWindow.Close()
		}
		subWindow.Show()
	})
	window.Show()
}

func subUI(configPath string, parent *widgets.QMainWindow) *widgets.QMainWindow {
	subWindow := widgets.NewQMainWindow(parent, 0)
	subWindow.SetFixedSize2(700, 300)
	subWindow.SetWindowTitle("subscription")

	subLabel := widgets.NewQLabel2("subscription", subWindow, core.Qt__WindowType(0x00000000))
	subLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 10), core.NewQPoint2(130, 40)))
	subCombobox := widgets.NewQComboBox(subWindow)
	link, err := configJSON.GetLink(configPath)
	if err != nil {
		log.Println(err)
		return new(widgets.QMainWindow)
	}
	subCombobox.AddItems(link)
	subCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 10), core.NewQPoint2(600, 40)))

	deleteButton := widgets.NewQPushButton2("delete", subWindow)
	deleteButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 10), core.NewQPoint2(690, 40)))

	plainText := widgets.NewQTextEdit(subWindow)
	plainText.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 50), core.NewQPoint2(600, 80)))

	addButton := widgets.NewQPushButton2("add", subWindow)
	addButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 50), core.NewQPoint2(690, 80)))
	//updateButton := widgets.NewQPushButton2("update",subWindow)
	//updateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(200,450),core.NewQPoint2(370,490)))
	return subWindow
}

func main() {
	configPath := ssr_init.GetConfigAndSQLPath()
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
		} else if *subDaemon == "httpBBp" {
			getdelay.StartHTTPByArgumentBypass()
		}
	} else {
		app := widgets.NewQApplication(len(os.Args), os.Args)
		SSRSub(configPath)
		app.Exec()
	}
}
