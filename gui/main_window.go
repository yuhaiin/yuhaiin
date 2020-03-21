package gui

import (
	"github.com/Asutorufa/SsrMicroClient/net/delay"
	"github.com/Asutorufa/SsrMicroClient/process/ssrcontrol"
	"github.com/Asutorufa/SsrMicroClient/subscription"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
	"log"
	"strconv"
)

func (ssrMicroClientGUI *SsrMicroClientGUI) createMainWindow() {
	ssrMicroClientGUI.MainWindow = widgets.NewQMainWindow(nil, 0)
	ssrMicroClientGUI.MainWindow.SetFixedSize2(600, 400)
	ssrMicroClientGUI.MainWindow.SetWindowTitle("SsrMicroClient")
	icon := gui.NewQIcon5(ssrMicroClientGUI.configPath + "/SsrMicroClient.png")
	ssrMicroClientGUI.MainWindow.SetWindowIcon(icon)

	trayIcon := widgets.NewQSystemTrayIcon(ssrMicroClientGUI.MainWindow)
	trayIcon.SetIcon(icon)
	menu := widgets.NewQMenu(nil)
	ssrMicroClientTrayIconMenu := widgets.NewQAction2("SsrMicroClient", ssrMicroClientGUI.MainWindow)
	ssrMicroClientTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		ssrMicroClientGUI.openMainWindow()
	})
	subscriptionTrayIconMenu := widgets.NewQAction2("subscription", ssrMicroClientGUI.MainWindow)
	subscriptionTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		ssrMicroClientGUI.openSubscriptionWindow()
	})

	settingTrayIconMenu := widgets.NewQAction2("setting", ssrMicroClientGUI.MainWindow)
	settingTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		ssrMicroClientGUI.openSettingWindow()
	})

	exit := widgets.NewQAction2("exit", ssrMicroClientGUI.MainWindow)
	exit.ConnectTriggered(func(bool2 bool) {
		ssrMicroClientGUI.App.Quit()
	})
	actions := []*widgets.QAction{ssrMicroClientTrayIconMenu,
		subscriptionTrayIconMenu, settingTrayIconMenu, exit}
	menu.AddActions(actions)
	trayIcon.SetContextMenu(menu)
	trayIcon.SetToolTip("")
	trayIcon.Show()

	statusLabel := widgets.NewQLabel2("status", ssrMicroClientGUI.MainWindow,
		core.Qt__WindowType(0x00000000))
	statusLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 10),
		core.NewQPoint2(130, 40)))
	statusLabel2 := widgets.NewQLabel2("", ssrMicroClientGUI.MainWindow,
		core.Qt__WindowType(0x00000000))
	statusLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 10),
		core.NewQPoint2(560, 40)))

	nowNodeLabel := widgets.NewQLabel2("now node", ssrMicroClientGUI.MainWindow,
		core.Qt__WindowType(0x00000000))
	nowNodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 60),
		core.NewQPoint2(130, 90)))
	nowNode, err := subscription.GetNowNode(ssrMicroClientGUI.configPath)
	if err != nil {
		ssrMicroClientGUI.MessageBox(err.Error())
		return
	}
	nowNodeLabel2 := widgets.NewQLabel2(nowNode["remarks"]+" - "+
		nowNode["group"], ssrMicroClientGUI.MainWindow, core.Qt__WindowType(0x00000000))
	nowNodeLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 60),
		core.NewQPoint2(560, 90)))

	groupLabel := widgets.NewQLabel2("group", ssrMicroClientGUI.MainWindow,
		core.Qt__WindowType(0x00000000))
	groupLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 110),
		core.NewQPoint2(130, 140)))
	groupCombobox := widgets.NewQComboBox(ssrMicroClientGUI.MainWindow)
	group, err := subscription.GetGroup(ssrMicroClientGUI.configPath)
	if err != nil {
		ssrMicroClientGUI.MessageBox(err.Error())
		return
	}
	groupCombobox.AddItems(group)
	groupCombobox.SetCurrentTextDefault(nowNode["group"])
	groupCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 110),
		core.NewQPoint2(450, 140)))
	refreshButton := widgets.NewQPushButton2("refresh", ssrMicroClientGUI.MainWindow)
	refreshButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 110),
		core.NewQPoint2(560, 140)))

	nodeLabel := widgets.NewQLabel2("node", ssrMicroClientGUI.MainWindow,
		core.Qt__WindowType(0x00000000))
	nodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 160),
		core.NewQPoint2(130, 190)))
	nodeCombobox := widgets.NewQComboBox(ssrMicroClientGUI.MainWindow)
	node, err := subscription.GetNode(ssrMicroClientGUI.configPath, groupCombobox.CurrentText())
	if err != nil {
		ssrMicroClientGUI.MessageBox(err.Error())
		return
	}
	nodeCombobox.AddItems(node)
	nodeCombobox.SetCurrentTextDefault(nowNode["remarks"])
	nodeCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 160),
		core.NewQPoint2(450, 190)))
	startButton := widgets.NewQPushButton2("start", ssrMicroClientGUI.MainWindow)

	// wait the last ssr process finished
	waitChan := make(chan bool, 0)
	go func() {
		waitChan <- true
	}()
	start := func() {
		if err := ssrMicroClientGUI.ssrCmd.Start(); err != nil {
			log.Println(err)
		}
		statusLabel2.SetText("<b><font color=green>running(pid:" + strconv.Itoa(ssrMicroClientGUI.ssrCmd.Process.Pid) + ")</font></b>")
		trayIcon.SetToolTip("running(pid:" + strconv.Itoa(ssrMicroClientGUI.ssrCmd.Process.Pid) + ")")
		if _, err := ssrMicroClientGUI.ssrCmd.Process.Wait(); err != nil {
			log.Println(err)
		}
		statusLabel2.SetText("<b><font color=red>stop</font></b>")
		trayIcon.SetToolTip("stop")
		waitChan <- true
	}
	startButton.ConnectClicked(func(bool2 bool) {
		group := groupCombobox.CurrentText()
		remarks := nodeCombobox.CurrentText()
		//_, exist := process.Get(ssrMicroClientGUI.configPath)
		log.Println(ssrMicroClientGUI.ssrCmd.Process, ssrMicroClientGUI.ssrCmd.ProcessState)
		if group == nowNode["group"] && remarks == nowNode["remarks"] && ssrMicroClientGUI.ssrCmd.Process != nil {
			if ssrMicroClientGUI.ssrCmd.Process.Pid != -1 {
				return
			}
		} else if group != nowNode["group"] || remarks != nowNode["remarks"] {
			err := subscription.ChangeNowNode2(ssrMicroClientGUI.configPath, group, remarks)
			if err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}
			nowNode, err = subscription.GetNowNode(ssrMicroClientGUI.configPath)
			if err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}
			nowNodeLabel2.SetText(nowNode["remarks"] + " - " + nowNode["group"])
			if ssrMicroClientGUI.ssrCmd.Process != nil {
				if err := ssrMicroClientGUI.ssrCmd.Process.Kill(); err != nil {
					log.Println(err)
				}
				ssrMicroClientGUI.ssrCmd = nil
			}
		}
		<-waitChan
		ssrMicroClientGUI.ssrCmd = ssrcontrol.GetSsrCmd(ssrMicroClientGUI.configPath)
		go func() {
			start()
		}()
	})

	startButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 160),
		core.NewQPoint2(560, 190)))

	delayLabel := widgets.NewQLabel2("delay", ssrMicroClientGUI.MainWindow,
		core.Qt__WindowType(0x00000000))
	delayLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 210),
		core.NewQPoint2(130, 240)))
	delayLabel2 := widgets.NewQLabel2("", ssrMicroClientGUI.MainWindow,
		core.Qt__WindowType(0x00000000))
	delayLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 210),
		core.NewQPoint2(450, 240)))
	delayButton := widgets.NewQPushButton2("get delay", ssrMicroClientGUI.MainWindow)
	delayButton.ConnectClicked(func(bool2 bool) {
		go func() {
			group := groupCombobox.CurrentText()
			remarks := nodeCombobox.CurrentText()
			node, err := subscription.GetOneNode(ssrMicroClientGUI.configPath, group, remarks)
			if err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}
			delayTmp, isSuccess, err := delay.TCPDelay(node.Server,
				node.ServerPort)
			var delayString string
			if err != nil {
				//ssrMicroClientGUI.MessageBox(err.Error())
				delayString = err.Error()
			} else {
				delayString = delayTmp.String()
			}
			if isSuccess == false {
				delayString = "delay > 3s or server can not connect"
			}
			delayLabel2.SetText(delayString)
		}()
	})
	delayButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 210),
		core.NewQPoint2(560, 240)))

	groupCombobox.ConnectCurrentTextChanged(func(string2 string) {
		node, err := subscription.GetNode(ssrMicroClientGUI.configPath,
			groupCombobox.CurrentText())
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)
	})

	subButton := widgets.NewQPushButton2("subscription setting", ssrMicroClientGUI.MainWindow)
	subButton.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 260),
		core.NewQPoint2(290, 290)))
	subButton.ConnectClicked(func(bool2 bool) {
		ssrMicroClientGUI.openSubscriptionWindow()
	})

	subUpdateButton := widgets.NewQPushButton2("subscription Update", ssrMicroClientGUI.MainWindow)
	subUpdateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 260),
		core.NewQPoint2(560, 290)))
	subUpdateButton.ConnectClicked(func(bool2 bool) {
		message := widgets.NewQMessageBox(ssrMicroClientGUI.MainWindow)
		message.SetText("Updating!")
		message.Show()
		if err := subscription.SsrJSON(ssrMicroClientGUI.configPath); err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}
		message.SetText("Updated!")
		group, err = subscription.GetGroup(ssrMicroClientGUI.configPath)
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}
		groupCombobox.Clear()
		groupCombobox.AddItems(group)
		groupCombobox.SetCurrentText(nowNode["group"])
		node, err = subscription.GetNode(ssrMicroClientGUI.configPath, groupCombobox.CurrentText())
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)
		nodeCombobox.SetCurrentText(nowNode["remarks"])
	})

	settingButton := widgets.NewQPushButton2("Setting", ssrMicroClientGUI.MainWindow)
	settingButton.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 300),
		core.NewQPoint2(290, 330)))
	settingButton.ConnectClicked(func(bool2 bool) {
		ssrMicroClientGUI.openSettingWindow()
	})

	if ssrMicroClientGUI.settingConfig.AutoStartSsr == true {
		if ssrMicroClientGUI.ssrCmd.Process != nil {
			if ssrMicroClientGUI.ssrCmd.Process.Pid != -1 {
				return
			}
		}
		startButton.Click()
	}
}
