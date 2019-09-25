package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"time"

	"../config/configjson"
	"../init"
	"../net"
	"../process"
	"../process/lockfile"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

type SsrMicroClientGUI struct {
	app                *widgets.QApplication
	mainWindow         *widgets.QMainWindow
	subscriptionWindow *widgets.QMainWindow
	settingWindow      *widgets.QMainWindow
	httpCmd            *exec.Cmd
	httpBypassCmd      *exec.Cmd
	socks5BypassCmd    *exec.Cmd
	configPath         string
	settingConfig      *configjson.Setting
}

func NewSsrMicroClientGUI(configPath string) (*SsrMicroClientGUI, error) {
	var err error
	microClientGUI := &SsrMicroClientGUI{}
	microClientGUI.configPath = configPath
	microClientGUI.settingConfig, err = configjson.SettingDecodeJSON(microClientGUI.configPath)
	if err != nil {
		return microClientGUI, err
	}
	microClientGUI.httpCmd, err = getdelay.GetHttpProxyCmd()
	if err != nil {
		return microClientGUI, err
	}
	microClientGUI.httpBypassCmd, err = getdelay.GetHttpProxyBypassCmd()
	if err != nil {
		return microClientGUI, err
	}
	microClientGUI.socks5BypassCmd, err = getdelay.GetSocks5ProxyBypassCmd()
	if err != nil {
		return microClientGUI, err
	}
	microClientGUI.app = widgets.NewQApplication(len(os.Args), os.Args)
	microClientGUI.app.SetApplicationName("SsrMicroClient")
	microClientGUI.app.SetQuitOnLastWindowClosed(false)
	microClientGUI.app.ConnectAboutToQuit(func() {
		if microClientGUI.httpBypassCmd.Process != nil {
			err = microClientGUI.httpBypassCmd.Process.Kill()
			if err != nil {
				//	do something
				//messageBox(err.Error() + " httpBypassCmd Kill")
			}
			_, err = microClientGUI.httpBypassCmd.Process.Wait()
			if err != nil {
				//	do something
				//messageBox(err.Error() + "httpBypassCmd wait")
			}
		}
		if microClientGUI.httpCmd.Process != nil {
			if err = microClientGUI.httpCmd.Process.Kill(); err != nil {
				//	do something
				//messageBox(err.Error() + " httpCmd kill")
			}

			if _, err = microClientGUI.httpCmd.Process.Wait(); err != nil {
				//	do something
				//messageBox(err.Error() + " httpCmd wait")
			}
		}
		if microClientGUI.socks5BypassCmd.Process != nil {
			err = microClientGUI.socks5BypassCmd.Process.Kill()
			if err != nil {
				//
				//messageBox(err.Error() + " socks5BypassCmd Kill")
			}
			_, err := microClientGUI.socks5BypassCmd.Process.Wait()
			if err != nil {
				//messageBox(err.Error() + " socks5BypassCmd wait")
				//
			}
		}
	})
	microClientGUI.mainWindow = widgets.NewQMainWindow(nil, 0)
	microClientGUI.createMainGUI()
	microClientGUI.subscriptionWindow = widgets.NewQMainWindow(microClientGUI.mainWindow, 0)
	microClientGUI.createSubWindow()
	microClientGUI.settingWindow = widgets.NewQMainWindow(microClientGUI.mainWindow, 0)
	microClientGUI.createSettingGUI()
	return microClientGUI, nil
}

func (ssrMicroClientGUI *SsrMicroClientGUI) beforeCreateGUI() {
	if ssrMicroClientGUI.settingConfig.HttpProxy == true && ssrMicroClientGUI.settingConfig.HttpWithBypass == true {
		err := ssrMicroClientGUI.httpBypassCmd.Start()
		if err != nil {
			log.Println(err)
		}
	} else if ssrMicroClientGUI.settingConfig.HttpProxy == true {
		err := ssrMicroClientGUI.httpCmd.Start()
		if err != nil {
			log.Println(err)
		}
	}
	if ssrMicroClientGUI.settingConfig.Socks5WithBypass == true {
		err := ssrMicroClientGUI.socks5BypassCmd.Start()
		if err != nil {
			log.Println(err)
		}
	}
}

func (ssrMicroClientGUI *SsrMicroClientGUI) createMainGUI() {
	ssrMicroClientGUI.mainWindow.SetFixedSize2(600, 400)
	ssrMicroClientGUI.mainWindow.SetWindowTitle("SsrMicroClient")
	//window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
	//	event.Ignore()
	//	window.Hide()
	//})
	icon := gui.NewQIcon5(ssrMicroClientGUI.configPath + "/SsrMicroClient.png")
	ssrMicroClientGUI.mainWindow.SetWindowIcon(icon)

	trayIcon := widgets.NewQSystemTrayIcon(ssrMicroClientGUI.mainWindow)
	trayIcon.SetIcon(icon)
	menu := widgets.NewQMenu(nil)
	ssrMicroClientTrayIconMenu := widgets.NewQAction2("SsrMicroClient", ssrMicroClientGUI.mainWindow)
	ssrMicroClientTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		if ssrMicroClientGUI.mainWindow.IsHidden() == false {
			ssrMicroClientGUI.mainWindow.Hide()
		}
		ssrMicroClientGUI.mainWindow.Show()
	})
	subscriptionTrayIconMenu := widgets.NewQAction2("subscription", ssrMicroClientGUI.mainWindow)
	subscriptionTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		if ssrMicroClientGUI.subscriptionWindow.IsHidden() == false {
			ssrMicroClientGUI.subscriptionWindow.Close()
		}
		ssrMicroClientGUI.subscriptionWindow.Show()
	})

	settingTrayIconMenu := widgets.NewQAction2("setting", ssrMicroClientGUI.mainWindow)
	settingTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		if ssrMicroClientGUI.settingWindow.IsHidden() == false {
			ssrMicroClientGUI.settingWindow.Close()
		}
		ssrMicroClientGUI.settingWindow.Show()
	})

	exit := widgets.NewQAction2("exit", ssrMicroClientGUI.mainWindow)
	exit.ConnectTriggered(func(bool2 bool) {
		ssrMicroClientGUI.app.Quit()
	})
	actions := []*widgets.QAction{ssrMicroClientTrayIconMenu,
		subscriptionTrayIconMenu, settingTrayIconMenu, exit}
	menu.AddActions(actions)
	trayIcon.SetContextMenu(menu)
	updateStatus := func() string {
		var status string
		if pid, run := process.Get(ssrMicroClientGUI.configPath); run == true {
			//switch runtime.GOOS {
			//default:
			status = "<b><font color=green>running (pid: " +
				pid + ")</font></b>"
			//case "windows":
			//	status = "running (pid: " +
			//		pid + ")"
			//}
		} else {
			//switch runtime.GOOS {
			//default:
			status = "<b><font color=reb>stopped</font></b>"
			//case "windows":
			status = "stopped"
			//}
		}
		return status
	}
	trayIcon.SetToolTip(updateStatus())
	trayIcon.Show()

	statusLabel := widgets.NewQLabel2("status", ssrMicroClientGUI.mainWindow,
		core.Qt__WindowType(0x00000000))
	statusLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 10),
		core.NewQPoint2(130, 40)))
	statusLabel2 := widgets.NewQLabel2(updateStatus(), ssrMicroClientGUI.mainWindow,
		core.Qt__WindowType(0x00000000))
	statusLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 10),
		core.NewQPoint2(560, 40)))

	nowNodeLabel := widgets.NewQLabel2("now node", ssrMicroClientGUI.mainWindow,
		core.Qt__WindowType(0x00000000))
	nowNodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 60),
		core.NewQPoint2(130, 90)))
	nowNode, err := configjson.GetNowNode(ssrMicroClientGUI.configPath)
	if err != nil {
		//log.Println(err)
		ssrMicroClientGUI.messageBox(err.Error())
		return
	}
	nowNodeLabel2 := widgets.NewQLabel2(nowNode["remarks"]+" - "+
		nowNode["group"], ssrMicroClientGUI.mainWindow, core.Qt__WindowType(0x00000000))
	nowNodeLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 60),
		core.NewQPoint2(560, 90)))

	groupLabel := widgets.NewQLabel2("group", ssrMicroClientGUI.mainWindow,
		core.Qt__WindowType(0x00000000))
	groupLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 110),
		core.NewQPoint2(130, 140)))
	groupCombobox := widgets.NewQComboBox(ssrMicroClientGUI.mainWindow)
	group, err := configjson.GetGroup(ssrMicroClientGUI.configPath)
	if err != nil {
		//log.Println(err)
		ssrMicroClientGUI.messageBox(err.Error())
		return
	}
	groupCombobox.AddItems(group)
	groupCombobox.SetCurrentTextDefault(nowNode["group"])
	groupCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 110),
		core.NewQPoint2(450, 140)))
	refreshButton := widgets.NewQPushButton2("refresh", ssrMicroClientGUI.mainWindow)
	refreshButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 110),
		core.NewQPoint2(560, 140)))

	nodeLabel := widgets.NewQLabel2("node", ssrMicroClientGUI.mainWindow,
		core.Qt__WindowType(0x00000000))
	nodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 160),
		core.NewQPoint2(130, 190)))
	nodeCombobox := widgets.NewQComboBox(ssrMicroClientGUI.mainWindow)
	node, err := configjson.GetNode(ssrMicroClientGUI.configPath, groupCombobox.CurrentText())
	if err != nil {
		//log.Println(err)
		ssrMicroClientGUI.messageBox(err.Error())
		return
	}
	nodeCombobox.AddItems(node)
	nodeCombobox.SetCurrentTextDefault(nowNode["remarks"])
	nodeCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 160),
		core.NewQPoint2(450, 190)))
	startButton := widgets.NewQPushButton2("start", ssrMicroClientGUI.mainWindow)
	startButton.ConnectClicked(func(bool2 bool) {
		group := groupCombobox.CurrentText()
		remarks := nodeCombobox.CurrentText()
		_, exist := process.Get(ssrMicroClientGUI.configPath)
		if group == nowNode["group"] && remarks ==
			nowNode["remarks"] && exist == true {
			return
		} else if group == nowNode["group"] && remarks ==
			nowNode["remarks"] && exist == false {
			process.StartByArgument(ssrMicroClientGUI.configPath, "ssr")
			var status string
			if pid, run := process.Get(ssrMicroClientGUI.configPath); run == true {
				status = "<b><font color=green>running (pid: " +
					pid + ")</font></b>"
			} else {
				status = "<b><font color=reb>stopped</font></b>"
			}
			statusLabel2.SetText(status)
			trayIcon.SetToolTip(updateStatus())
		} else {
			err := configjson.ChangeNowNode2(ssrMicroClientGUI.configPath, group, remarks)
			if err != nil {
				ssrMicroClientGUI.messageBox(err.Error())
				return
			}
			nowNode, err = configjson.GetNowNode(ssrMicroClientGUI.configPath)
			if err != nil {
				//log.Println(err)
				ssrMicroClientGUI.messageBox(err.Error())
				return
			}
			nowNodeLabel2.SetText(nowNode["remarks"] + " - " +
				nowNode["group"])
			if exist == true {
				process.Stop(ssrMicroClientGUI.configPath)
				// ssr_process.Start(path, db_path)
				time.Sleep(250 * time.Millisecond)
				process.StartByArgument(ssrMicroClientGUI.configPath, "ssr")
			} else {
				process.StartByArgument(ssrMicroClientGUI.configPath, "ssr")
			}
			var status string
			if pid, run := process.Get(ssrMicroClientGUI.configPath); run == true {
				status = "<b><font color=green>running (pid: " +
					pid + ")</font></b>"
			} else {
				status = "<b><font color=reb>stopped</font></b>"
			}
			statusLabel2.SetText(status)
			trayIcon.SetToolTip(updateStatus())
		}
	})
	startButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 160),
		core.NewQPoint2(560, 190)))

	delayLabel := widgets.NewQLabel2("delay", ssrMicroClientGUI.mainWindow,
		core.Qt__WindowType(0x00000000))
	delayLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 210),
		core.NewQPoint2(130, 240)))
	delayLabel2 := widgets.NewQLabel2("", ssrMicroClientGUI.mainWindow,
		core.Qt__WindowType(0x00000000))
	delayLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 210),
		core.NewQPoint2(450, 240)))
	delayButton := widgets.NewQPushButton2("get delay", ssrMicroClientGUI.mainWindow)
	delayButton.ConnectClicked(func(bool2 bool) {
		group := groupCombobox.CurrentText()
		remarks := nodeCombobox.CurrentText()
		node, err := configjson.GetOneNode(ssrMicroClientGUI.configPath, group, remarks)
		if err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
			return
		}
		delay, isSuccess, err := getdelay.TCPDelay(node.Server,
			node.ServerPort)
		var delayString string
		if err != nil {
			ssrMicroClientGUI.messageBox(err.Error())
		} else {
			delayString = delay.String()
		}
		if isSuccess == false {
			delayString = "delay > 3s or server can not connect"
		}
		delayLabel2.SetText(delayString)
	})
	delayButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 210),
		core.NewQPoint2(560, 240)))

	groupCombobox.ConnectCurrentTextChanged(func(string2 string) {
		node, err := configjson.GetNode(ssrMicroClientGUI.configPath,
			groupCombobox.CurrentText())
		if err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)
	})

	subButton := widgets.NewQPushButton2("subscription setting", ssrMicroClientGUI.mainWindow)
	subButton.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 260),
		core.NewQPoint2(290, 290)))
	subButton.ConnectClicked(func(bool2 bool) {
		if ssrMicroClientGUI.subscriptionWindow.IsHidden() == false {
			ssrMicroClientGUI.subscriptionWindow.Close()
		}
		ssrMicroClientGUI.subscriptionWindow.Show()
	})

	subUpdateButton := widgets.NewQPushButton2("subscription Update", ssrMicroClientGUI.mainWindow)
	subUpdateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 260),
		core.NewQPoint2(560, 290)))
	subUpdateButton.ConnectClicked(func(bool2 bool) {
		message := widgets.NewQMessageBox(ssrMicroClientGUI.mainWindow)
		message.SetText("Updating!")
		message.Show()
		if err := configjson.SsrJSON(ssrMicroClientGUI.configPath); err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
		}
		message.SetText("Updated!")
		group, err = configjson.GetGroup(ssrMicroClientGUI.configPath)
		if err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
			return
		}
		groupCombobox.Clear()
		groupCombobox.AddItems(group)
		groupCombobox.SetCurrentText(nowNode["group"])
		node, err = configjson.GetNode(ssrMicroClientGUI.configPath, groupCombobox.CurrentText())
		if err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
			return
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)
		nodeCombobox.SetCurrentText(nowNode["remarks"])

	})

	if ssrMicroClientGUI.settingConfig.AutoStartSsr == true {
		if _, exist := process.Get(ssrMicroClientGUI.configPath); !exist {
			startButton.Click()
		}
	}
}

func (ssrMicroClientGUI *SsrMicroClientGUI) createSubWindow() {
	ssrMicroClientGUI.subscriptionWindow.SetFixedSize2(700, 100)
	ssrMicroClientGUI.subscriptionWindow.SetWindowTitle("subscription")
	ssrMicroClientGUI.subscriptionWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		ssrMicroClientGUI.subscriptionWindow.Hide()
	})

	subLabel := widgets.NewQLabel2("subscription", ssrMicroClientGUI.subscriptionWindow,
		core.Qt__WindowType(0x00000000))
	subLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 10),
		core.NewQPoint2(130, 40)))
	subCombobox := widgets.NewQComboBox(ssrMicroClientGUI.subscriptionWindow)
	var link []string
	subRefresh := func() {
		subCombobox.Clear()
		var err error
		link, err = configjson.GetLink(ssrMicroClientGUI.configPath)
		if err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
		}
		subCombobox.AddItems(link)
	}
	subRefresh()
	subCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 10),
		core.NewQPoint2(600, 40)))

	deleteButton := widgets.NewQPushButton2("delete", ssrMicroClientGUI.subscriptionWindow)
	deleteButton.ConnectClicked(func(bool2 bool) {
		linkToDelete := subCombobox.CurrentText()
		if err := configjson.RemoveLinkJSON2(linkToDelete,
			ssrMicroClientGUI.configPath); err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
		}
		subRefresh()
	})
	deleteButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 10),
		core.NewQPoint2(690, 40)))

	lineText := widgets.NewQLineEdit(ssrMicroClientGUI.subscriptionWindow)
	lineText.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 50),
		core.NewQPoint2(600, 80)))

	addButton := widgets.NewQPushButton2("add", ssrMicroClientGUI.subscriptionWindow)
	addButton.ConnectClicked(func(bool2 bool) {
		linkToAdd := lineText.Text()
		if linkToAdd == "" {
			return
		}
		for _, linkExisted := range link {
			if linkExisted == linkToAdd {
				return
			}
		}
		if err := configjson.AddLinkJSON2(linkToAdd, ssrMicroClientGUI.configPath); err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
			return
		}
		subRefresh()
	})
	addButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 50),
		core.NewQPoint2(690, 80)))
	//updateButton := widgets.NewQPushButton2("update",subWindow)
	//updateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(200,450),core.NewQPoint2(370,490)))

	ssrMicroClientGUI.subscriptionWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		ssrMicroClientGUI.subscriptionWindow.Close()
	})
}

func (ssrMicroClientGUI *SsrMicroClientGUI) createSettingGUI() {
	ssrMicroClientGUI.settingWindow.SetFixedSize2(430, 330)
	ssrMicroClientGUI.settingWindow.SetWindowTitle("setting")
	ssrMicroClientGUI.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		ssrMicroClientGUI.settingWindow.Hide()
	})

	autoStartSsr := widgets.NewQCheckBox2("auto Start ssr", ssrMicroClientGUI.settingWindow)
	autoStartSsr.SetChecked(ssrMicroClientGUI.settingConfig.AutoStartSsr)
	autoStartSsr.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0),
		core.NewQPoint2(490, 30)))

	httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", ssrMicroClientGUI.settingWindow)
	httpProxyCheckBox.SetChecked(ssrMicroClientGUI.settingConfig.HttpProxy)
	httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40),
		core.NewQPoint2(130, 70)))

	socks5BypassCheckBox := widgets.NewQCheckBox2("socks5 bypass",
		ssrMicroClientGUI.settingWindow)
	socks5BypassCheckBox.SetChecked(ssrMicroClientGUI.settingConfig.Socks5WithBypass)
	socks5BypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(140, 40),
		core.NewQPoint2(290, 70)))

	httpBypassCheckBox := widgets.NewQCheckBox2("http bypass", ssrMicroClientGUI.settingWindow)
	httpBypassCheckBox.SetChecked(ssrMicroClientGUI.settingConfig.HttpWithBypass)
	httpBypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 40),
		core.NewQPoint2(450, 70)))

	localAddressLabel := widgets.NewQLabel2("address", ssrMicroClientGUI.settingWindow, 0)
	localAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80),
		core.NewQPoint2(80, 110)))
	localAddressLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	localAddressLineText.SetText(ssrMicroClientGUI.settingConfig.LocalAddress)
	localAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(90, 80),
		core.NewQPoint2(200, 110)))

	localPortLabel := widgets.NewQLabel2("port", ssrMicroClientGUI.settingWindow, 0)
	localPortLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 80),
		core.NewQPoint2(300, 110)))
	localPortLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	localPortLineText.SetText(ssrMicroClientGUI.settingConfig.LocalPort)
	localPortLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 80),
		core.NewQPoint2(420, 110)))

	httpAddressLabel := widgets.NewQLabel2("http", ssrMicroClientGUI.settingWindow, 0)
	httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120),
		core.NewQPoint2(70, 150)))
	httpAddressLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	httpAddressLineText.SetText(ssrMicroClientGUI.settingConfig.HttpProxyAddressAndPort)
	httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120),
		core.NewQPoint2(210, 150)))

	socks5BypassAddressLabel := widgets.NewQLabel2("socks5Bp",
		ssrMicroClientGUI.settingWindow, 0)
	socks5BypassAddressLabel.SetGeometry(core.
		NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
	socks5BypassLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	socks5BypassLineText.SetText(ssrMicroClientGUI.settingConfig.Socks5WithBypassAddressAndPort)
	socks5BypassLineText.SetGeometry(core.NewQRect2(core.
		NewQPoint2(300, 120), core.NewQPoint2(420, 150)))

	pythonPathLabel := widgets.NewQLabel2("pythonPath", ssrMicroClientGUI.settingWindow, 0)
	pythonPathLabel.SetGeometry(core.NewQRect2(core.
		NewQPoint2(10, 160), core.NewQPoint2(100, 190)))
	pythonPathLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	pythonPathLineText.SetText(ssrMicroClientGUI.settingConfig.PythonPath)
	pythonPathLineText.SetGeometry(core.NewQRect2(core.
		NewQPoint2(110, 160), core.NewQPoint2(420, 190)))

	ssrPathLabel := widgets.NewQLabel2("ssrPath", ssrMicroClientGUI.settingWindow, 0)
	ssrPathLabel.SetGeometry(core.NewQRect2(core.
		NewQPoint2(10, 200), core.NewQPoint2(100, 230)))
	ssrPathLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	ssrPathLineText.SetText(ssrMicroClientGUI.settingConfig.SsrPath)
	ssrPathLineText.SetGeometry(core.NewQRect2(core.
		NewQPoint2(110, 200), core.NewQPoint2(420, 230)))

	BypassFileLabel := widgets.NewQLabel2("ssrPath", ssrMicroClientGUI.settingWindow, 0)
	BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240),
		core.NewQPoint2(100, 270)))
	BypassFileLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	BypassFileLineText.SetText(ssrMicroClientGUI.settingConfig.BypassFile)
	BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 240),
		core.NewQPoint2(420, 270)))

	applyButton := widgets.NewQPushButton2("apply", ssrMicroClientGUI.settingWindow)
	applyButton.ConnectClicked(func(bool2 bool) {
		ssrMicroClientGUI.settingConfig.AutoStartSsr = autoStartSsr.IsChecked()
		ssrMicroClientGUI.settingConfig.HttpProxy = httpProxyCheckBox.IsChecked()
		ssrMicroClientGUI.settingConfig.Socks5WithBypass = socks5BypassCheckBox.IsChecked()
		ssrMicroClientGUI.settingConfig.HttpWithBypass = httpBypassCheckBox.IsChecked()
		ssrMicroClientGUI.settingConfig.LocalAddress = localAddressLineText.Text()
		ssrMicroClientGUI.settingConfig.LocalPort = localPortLineText.Text()
		ssrMicroClientGUI.settingConfig.PythonPath = pythonPathLineText.Text()
		ssrMicroClientGUI.settingConfig.SsrPath = ssrPathLineText.Text()
		ssrMicroClientGUI.settingConfig.BypassFile = BypassFileLineText.Text()

		if err := configjson.SettingEnCodeJSON(ssrMicroClientGUI.configPath, ssrMicroClientGUI.settingConfig); err != nil {
			//log.Println(err)
			ssrMicroClientGUI.messageBox(err.Error())
		}

		if httpAddressLineText.Text() !=
			ssrMicroClientGUI.settingConfig.HttpProxyAddressAndPort || ssrMicroClientGUI.settingConfig.HttpProxy !=
			httpProxyCheckBox.IsChecked() || ssrMicroClientGUI.settingConfig.HttpWithBypass !=
			httpBypassCheckBox.IsChecked() {
			ssrMicroClientGUI.settingConfig.HttpProxyAddressAndPort = httpAddressLineText.Text()
			if ssrMicroClientGUI.settingConfig.HttpProxy == true &&
				ssrMicroClientGUI.settingConfig.HttpWithBypass == true {
				if ssrMicroClientGUI.httpBypassCmd.Process != nil {
					if err := ssrMicroClientGUI.httpBypassCmd.Process.Kill(); err != nil {
						//log.Println(err)
						ssrMicroClientGUI.messageBox(err.Error())
					}
					if _, err := ssrMicroClientGUI.httpBypassCmd.Process.Wait(); err != nil {
						ssrMicroClientGUI.messageBox(err.Error())
					}
				}
			} else if ssrMicroClientGUI.settingConfig.HttpProxy == true {
				if ssrMicroClientGUI.httpCmd.Process != nil {
					if err := ssrMicroClientGUI.httpCmd.Process.Kill(); err != nil {
						//log.Println(err)
						ssrMicroClientGUI.messageBox(err.Error())
					}

					if _, err := ssrMicroClientGUI.httpCmd.Process.Wait(); err != nil {
						ssrMicroClientGUI.messageBox(err.Error())
					}
				}
			}
			ssrMicroClientGUI.settingConfig.HttpProxy = httpProxyCheckBox.IsChecked()
			ssrMicroClientGUI.settingConfig.HttpWithBypass = httpBypassCheckBox.IsChecked()

			if err := configjson.SettingEnCodeJSON(ssrMicroClientGUI.configPath, ssrMicroClientGUI.settingConfig); err != nil {
				//log.Println(err)
				ssrMicroClientGUI.messageBox(err.Error())
			}
			if ssrMicroClientGUI.settingConfig.HttpProxy == true &&
				ssrMicroClientGUI.settingConfig.HttpWithBypass == true {
				var err error
				ssrMicroClientGUI.httpBypassCmd, err = getdelay.GetHttpProxyBypassCmd()
				if err != nil {
					ssrMicroClientGUI.messageBox(err.Error())
				}
				if err = ssrMicroClientGUI.httpBypassCmd.Start(); err != nil {
					ssrMicroClientGUI.messageBox(err.Error())
				}
			} else if ssrMicroClientGUI.settingConfig.HttpProxy == true {
				var err error
				ssrMicroClientGUI.httpCmd, err = getdelay.GetHttpProxyCmd()
				if err != nil {
					ssrMicroClientGUI.messageBox(err.Error())
				}

				if err = ssrMicroClientGUI.httpCmd.Start(); err != nil {
					ssrMicroClientGUI.messageBox(err.Error())
				}
			}
		}
		if ssrMicroClientGUI.settingConfig.Socks5WithBypassAddressAndPort !=
			socks5BypassLineText.Text() || ssrMicroClientGUI.settingConfig.Socks5WithBypass !=
			socks5BypassCheckBox.IsChecked() {
			ssrMicroClientGUI.settingConfig.Socks5WithBypass = socks5BypassCheckBox.IsChecked()
			ssrMicroClientGUI.settingConfig.Socks5WithBypassAddressAndPort =
				socks5BypassLineText.Text()
			if err := configjson.SettingEnCodeJSON(ssrMicroClientGUI.configPath, ssrMicroClientGUI.settingConfig); err != nil {
				//log.Println(err)
				ssrMicroClientGUI.messageBox(err.Error())
			}
			if ssrMicroClientGUI.socks5BypassCmd.Process != nil {
				if err := ssrMicroClientGUI.socks5BypassCmd.Process.Kill(); err != nil {
					//log.Println(err)
					ssrMicroClientGUI.messageBox(err.Error())
				}
				if _, err := ssrMicroClientGUI.socks5BypassCmd.Process.Wait(); err != nil {
					ssrMicroClientGUI.messageBox(err.Error())
				}
			}
			var err error
			ssrMicroClientGUI.socks5BypassCmd, err = getdelay.GetSocks5ProxyBypassCmd()
			if err != nil {
				ssrMicroClientGUI.messageBox(err.Error())
			}
			if err := ssrMicroClientGUI.socks5BypassCmd.Start(); err != nil {
				ssrMicroClientGUI.messageBox(err.Error())
			}
		}
		//else {
		//	httpProxyCheckBox.SetChecked(settingConfig.HttpProxy)
		//	socks5BypassCheckBox.SetChecked(settingConfig.Socks5WithBypass)
		//	httpBypassCheckBox.SetChecked(settingConfig.HttpWithBypass)
		//	localAddressLineText.SetText(settingConfig.LocalAddress)
		//	localPortLineText.SetText(settingConfig.LocalPort)
		//	httpAddressLineText.SetText(settingConfig.HttpProxyAddressAndPort)
		//	pythonPathLineText.SetText(settingConfig.PythonPath)
		//	ssrPathLineText.SetText(settingConfig.SsrPath)
		//	BypassFileLineText.SetText(settingConfig.BypassFile)
		//}
	})
	applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280),
		core.NewQPoint2(90, 310)))

	ssrMicroClientGUI.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		ssrMicroClientGUI.settingWindow.Close()
	})
}

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
		ssrMicroClientGUI, err := NewSsrMicroClientGUI(configPath)
		if err != nil && ssrMicroClientGUI != nil {
			ssrMicroClientGUI.messageBox(err.Error())
		}

		lockFile, err := os.Create(configPath +
			"/SsrMicroClientRunStatuesLockFile")
		if err != nil {
			ssrMicroClientGUI.messageBox(err.Error())
			return
		}

		if err = lockfile.LockFile(lockFile); err != nil {
			ssrMicroClientGUI.messageBox("process is exist!\n" + err.Error())
			return
		} else {
			defer lockFile.Close()
			defer os.Remove(configPath + "/SsrMicroClientRunStatuesLockFile")
		}
		ssrMicroClientGUI.mainWindow.Show()
		ssrMicroClientGUI.app.Exec()
	}
}

func (ssrMicroClientGUI *SsrMicroClientGUI) messageBox(text string) {
	message := widgets.NewQMessageBox(nil)
	message.SetText(text)
	message.Exec()
}

//
//func SSRSub(configPath string, parent *widgets.QApplication) {
//	httpCmd, err := getdelay.GetHttpProxyCmd()
//	if err != nil {
//		log.Println(err)
//	}
//	httpBypassCmd, err := getdelay.GetHttpProxyBypassCmd()
//	if err != nil {
//		log.Println(err)
//	}
//	socks5BypassCmd, err := getdelay.GetSocks5ProxyBypassCmd()
//	if err != nil {
//		log.Println(err)
//	}
//	setting, err := configjson.SettingDecodeJSON(configPath)
//	if err != nil {
//		log.Println(err)
//	}
//
//	parent.ConnectAboutToQuit(func() {
//		if httpBypassCmd.Process != nil {
//			err = httpBypassCmd.Process.Kill()
//			if err != nil {
//				//	do something
//				messageBox(err.Error() + " httpBypassCmd Kill")
//			}
//			_, err = httpBypassCmd.Process.Wait()
//			if err != nil {
//				//	do something
//				messageBox(err.Error() + "httpBypassCmd wait")
//			}
//		}
//		if httpCmd.Process != nil {
//			if err = httpCmd.Process.Kill(); err != nil {
//				//	do something
//				messageBox(err.Error() + " httpCmd kill")
//			}
//
//			if _, err = httpCmd.Process.Wait(); err != nil {
//				//	do something
//				messageBox(err.Error() + " httpCmd wait")
//			}
//		}
//		if socks5BypassCmd.Process != nil {
//			err = socks5BypassCmd.Process.Kill()
//			if err != nil {
//				//
//				messageBox(err.Error() + " socks5BypassCmd Kill")
//			}
//			_, err := socks5BypassCmd.Process.Wait()
//			if err != nil {
//				messageBox(err.Error() + " socks5BypassCmd wait")
//				//
//			}
//		}
//	})
//
//	if setting.HttpProxy == true && setting.HttpWithBypass == true {
//		err = httpBypassCmd.Start()
//		if err != nil {
//			log.Println(err)
//		}
//	} else if setting.HttpProxy == true {
//		err = httpCmd.Start()
//		if err != nil {
//			log.Println(err)
//		}
//	}
//	if setting.Socks5WithBypass == true {
//		err = socks5BypassCmd.Start()
//		if err != nil {
//			log.Println(err)
//		}
//	}
//	window := widgets.NewQMainWindow(nil, 0)
//	//window.SetMinimumSize2(600, 400)
//	window.SetFixedSize2(600, 400)
//	window.SetWindowTitle("SsrMicroClient")
//	//window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
//	//	event.Ignore()
//	//	window.Hide()
//	//})
//	icon := gui.NewQIcon5(configPath + "/SsrMicroClient.png")
//	window.SetWindowIcon(icon)
//
//	subWindow := subUI(configPath, window)
//	settingWindow, err := SsrMicroClientSetting(window, httpCmd, httpBypassCmd,
//		socks5BypassCmd, configPath)
//	if err != nil {
//		messageBox(err.Error())
//	}
//
//	trayIcon := widgets.NewQSystemTrayIcon(window)
//	trayIcon.SetIcon(icon)
//	menu := widgets.NewQMenu(nil)
//	ssrMicroClientTrayIconMenu := widgets.NewQAction2("SsrMicroClient", window)
//	ssrMicroClientTrayIconMenu.ConnectTriggered(func(bool2 bool) {
//		if window.IsHidden() == false {
//			window.Hide()
//		}
//		window.Show()
//	})
//	subscriptionTrayIconMenu := widgets.NewQAction2("subscription", window)
//	subscriptionTrayIconMenu.ConnectTriggered(func(bool2 bool) {
//		if subWindow.IsHidden() == false {
//			subWindow.Close()
//		}
//		subWindow.Show()
//	})
//
//	settingTrayIconMenu := widgets.NewQAction2("setting", window)
//	settingTrayIconMenu.ConnectTriggered(func(bool2 bool) {
//		if settingWindow.IsHidden() == false {
//			settingWindow.Close()
//		}
//		settingWindow.Show()
//	})
//
//	exit := widgets.NewQAction2("exit", window)
//	exit.ConnectTriggered(func(bool2 bool) {
//		parent.Quit()
//	})
//	actions := []*widgets.QAction{ssrMicroClientTrayIconMenu,
//		subscriptionTrayIconMenu, settingTrayIconMenu, exit}
//	menu.AddActions(actions)
//	trayIcon.SetContextMenu(menu)
//	updateStatus := func() string {
//		var status string
//		if pid, run := process.Get(configPath); run == true {
//			//switch runtime.GOOS {
//			//default:
//			status = "<b><font color=green>running (pid: " +
//				pid + ")</font></b>"
//			//case "windows":
//			//	status = "running (pid: " +
//			//		pid + ")"
//			//}
//		} else {
//			//switch runtime.GOOS {
//			//default:
//			status = "<b><font color=reb>stopped</font></b>"
//			//case "windows":
//			status = "stopped"
//			//}
//		}
//		return status
//	}
//	trayIcon.SetToolTip(updateStatus())
//	trayIcon.Show()
//
//	statusLabel := widgets.NewQLabel2("status", window,
//		core.Qt__WindowType(0x00000000))
//	statusLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 10),
//		core.NewQPoint2(130, 40)))
//	statusLabel2 := widgets.NewQLabel2(updateStatus(), window,
//		core.Qt__WindowType(0x00000000))
//	statusLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 10),
//		core.NewQPoint2(560, 40)))
//
//	nowNodeLabel := widgets.NewQLabel2("now node", window,
//		core.Qt__WindowType(0x00000000))
//	nowNodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 60),
//		core.NewQPoint2(130, 90)))
//	nowNode, err := configjson.GetNowNode(configPath)
//	if err != nil {
//		//log.Println(err)
//		messageBox(err.Error())
//		return
//	}
//	nowNodeLabel2 := widgets.NewQLabel2(nowNode["remarks"]+" - "+
//		nowNode["group"], window, core.Qt__WindowType(0x00000000))
//	nowNodeLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 60),
//		core.NewQPoint2(560, 90)))
//
//	groupLabel := widgets.NewQLabel2("group", window,
//		core.Qt__WindowType(0x00000000))
//	groupLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 110),
//		core.NewQPoint2(130, 140)))
//	groupCombobox := widgets.NewQComboBox(window)
//	group, err := configjson.GetGroup(configPath)
//	if err != nil {
//		//log.Println(err)
//		messageBox(err.Error())
//		return
//	}
//	groupCombobox.AddItems(group)
//	groupCombobox.SetCurrentTextDefault(nowNode["group"])
//	groupCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 110),
//		core.NewQPoint2(450, 140)))
//	refreshButton := widgets.NewQPushButton2("refresh", window)
//	refreshButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 110),
//		core.NewQPoint2(560, 140)))
//
//	nodeLabel := widgets.NewQLabel2("node", window,
//		core.Qt__WindowType(0x00000000))
//	nodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 160),
//		core.NewQPoint2(130, 190)))
//	nodeCombobox := widgets.NewQComboBox(window)
//	node, err := configjson.GetNode(configPath, groupCombobox.CurrentText())
//	if err != nil {
//		//log.Println(err)
//		messageBox(err.Error())
//		return
//	}
//	nodeCombobox.AddItems(node)
//	nodeCombobox.SetCurrentTextDefault(nowNode["remarks"])
//	nodeCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 160),
//		core.NewQPoint2(450, 190)))
//	startButton := widgets.NewQPushButton2("start", window)
//	startButton.ConnectClicked(func(bool2 bool) {
//		group := groupCombobox.CurrentText()
//		remarks := nodeCombobox.CurrentText()
//		_, exist := process.Get(configPath)
//		if group == nowNode["group"] && remarks ==
//			nowNode["remarks"] && exist == true {
//			return
//		} else if group == nowNode["group"] && remarks ==
//			nowNode["remarks"] && exist == false {
//			process.StartByArgument(configPath, "ssr")
//			var status string
//			if pid, run := process.Get(configPath); run == true {
//				status = "<b><font color=green>running (pid: " +
//					pid + ")</font></b>"
//			} else {
//				status = "<b><font color=reb>stopped</font></b>"
//			}
//			statusLabel2.SetText(status)
//			trayIcon.SetToolTip(updateStatus())
//		} else {
//			err := configjson.ChangeNowNode2(configPath, group, remarks)
//			if err != nil {
//				messageBox(err.Error())
//				return
//			}
//			nowNode, err = configjson.GetNowNode(configPath)
//			if err != nil {
//				//log.Println(err)
//				messageBox(err.Error())
//				return
//			}
//			nowNodeLabel2.SetText(nowNode["remarks"] + " - " +
//				nowNode["group"])
//			if exist == true {
//				process.Stop(configPath)
//				// ssr_process.Start(path, db_path)
//				time.Sleep(250 * time.Millisecond)
//				process.StartByArgument(configPath, "ssr")
//			} else {
//				process.StartByArgument(configPath, "ssr")
//			}
//			var status string
//			if pid, run := process.Get(configPath); run == true {
//				status = "<b><font color=green>running (pid: " +
//					pid + ")</font></b>"
//			} else {
//				status = "<b><font color=reb>stopped</font></b>"
//			}
//			statusLabel2.SetText(status)
//			trayIcon.SetToolTip(updateStatus())
//		}
//	})
//	startButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 160),
//		core.NewQPoint2(560, 190)))
//
//	delayLabel := widgets.NewQLabel2("delay", window,
//		core.Qt__WindowType(0x00000000))
//	delayLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 210),
//		core.NewQPoint2(130, 240)))
//	delayLabel2 := widgets.NewQLabel2("", window,
//		core.Qt__WindowType(0x00000000))
//	delayLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 210),
//		core.NewQPoint2(450, 240)))
//	delayButton := widgets.NewQPushButton2("get delay", window)
//	delayButton.ConnectClicked(func(bool2 bool) {
//		group := groupCombobox.CurrentText()
//		remarks := nodeCombobox.CurrentText()
//		node, err := configjson.GetOneNode(configPath, group, remarks)
//		if err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//			return
//		}
//		delay, isSuccess, err := getdelay.TCPDelay(node.Server,
//			node.ServerPort)
//		var delayString string
//		if err != nil {
//			messageBox(err.Error())
//		} else {
//			delayString = delay.String()
//		}
//		if isSuccess == false {
//			delayString = "delay > 3s or server can not connect"
//		}
//		delayLabel2.SetText(delayString)
//	})
//	delayButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 210),
//		core.NewQPoint2(560, 240)))
//
//	groupCombobox.ConnectCurrentTextChanged(func(string2 string) {
//		node, err := configjson.GetNode(configPath,
//			groupCombobox.CurrentText())
//		if err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//		}
//		nodeCombobox.Clear()
//		nodeCombobox.AddItems(node)
//	})
//
//	subButton := widgets.NewQPushButton2("subscription setting", window)
//	subButton.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 260),
//		core.NewQPoint2(290, 290)))
//	subButton.ConnectClicked(func(bool2 bool) {
//		if subWindow.IsHidden() == false {
//			subWindow.Close()
//		}
//		subWindow.Show()
//	})
//
//	subUpdateButton := widgets.NewQPushButton2("subscription Update", window)
//	subUpdateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 260),
//		core.NewQPoint2(560, 290)))
//	subUpdateButton.ConnectClicked(func(bool2 bool) {
//		message := widgets.NewQMessageBox(window)
//		message.SetText("Updating!")
//		message.Show()
//		if err := configjson.SsrJSON(configPath); err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//		}
//		message.SetText("Updated!")
//		group, err = configjson.GetGroup(configPath)
//		if err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//			return
//		}
//		groupCombobox.Clear()
//		groupCombobox.AddItems(group)
//		groupCombobox.SetCurrentText(nowNode["group"])
//		node, err = configjson.GetNode(configPath, groupCombobox.CurrentText())
//		if err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//			return
//		}
//		nodeCombobox.Clear()
//		nodeCombobox.AddItems(node)
//		nodeCombobox.SetCurrentText(nowNode["remarks"])
//
//	})
//
//	if setting.AutoStartSsr == true {
//		if _, exist := process.Get(configPath); !exist {
//			startButton.Click()
//		}
//	}
//	window.Show()
//}
//
//func subUI(configPath string,
//	parent *widgets.QMainWindow) *widgets.QMainWindow {
//	subWindow := widgets.NewQMainWindow(parent, 0)
//	subWindow.SetFixedSize2(700, 100)
//	subWindow.SetWindowTitle("subscription")
//	subWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
//		event.Ignore()
//		subWindow.Hide()
//	})
//
//	subLabel := widgets.NewQLabel2("subscription", subWindow,
//		core.Qt__WindowType(0x00000000))
//	subLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 10),
//		core.NewQPoint2(130, 40)))
//	subCombobox := widgets.NewQComboBox(subWindow)
//	var link []string
//	subRefresh := func() {
//		subCombobox.Clear()
//		var err error
//		link, err = configjson.GetLink(configPath)
//		if err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//		}
//		subCombobox.AddItems(link)
//	}
//	subRefresh()
//	subCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 10),
//		core.NewQPoint2(600, 40)))
//
//	deleteButton := widgets.NewQPushButton2("delete", subWindow)
//	deleteButton.ConnectClicked(func(bool2 bool) {
//		linkToDelete := subCombobox.CurrentText()
//		if err := configjson.RemoveLinkJSON2(linkToDelete,
//			configPath); err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//		}
//		subRefresh()
//	})
//	deleteButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 10),
//		core.NewQPoint2(690, 40)))
//
//	lineText := widgets.NewQLineEdit(subWindow)
//	lineText.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 50),
//		core.NewQPoint2(600, 80)))
//
//	addButton := widgets.NewQPushButton2("add", subWindow)
//	addButton.ConnectClicked(func(bool2 bool) {
//		linkToAdd := lineText.Text()
//		if linkToAdd == "" {
//			return
//		}
//		for _, linkExisted := range link {
//			if linkExisted == linkToAdd {
//				return
//			}
//		}
//		if err := configjson.AddLinkJSON2(linkToAdd, configPath); err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//			return
//		}
//		subRefresh()
//	})
//	addButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 50),
//		core.NewQPoint2(690, 80)))
//	//updateButton := widgets.NewQPushButton2("update",subWindow)
//	//updateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(200,450),core.NewQPoint2(370,490)))
//
//	subWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
//		subWindow.Close()
//	})
//	return subWindow
//}
//
//func SsrMicroClientSetting(parent *widgets.QMainWindow, http, httpBypass,
//	socks5Bypass *exec.Cmd, configPath string) (*widgets.QMainWindow, error) {
//	settingConfig, err := configjson.SettingDecodeJSON(configPath)
//	if err != nil {
//		//log.Println(err)
//		messageBox(err.Error())
//		return widgets.NewQMainWindow(nil, 0), err
//	}
//	settingWindow := widgets.NewQMainWindow(parent, 0)
//	settingWindow.SetFixedSize2(430, 330)
//	settingWindow.SetWindowTitle("setting")
//	settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
//		event.Ignore()
//		settingWindow.Hide()
//	})
//
//	//httpProxyStat := widgets.NewQLabel(settingWindow, 0)
//	//if http.ProcessState != nil {
//	//	httpProxyStat.SetText("<center><b><font color=green>http proxy now running!</font></b></center>")
//	//} else if httpBypass.ProcessState != nil {
//	//	httpProxyStat.SetText("<center><b><font color=green>http proxy with bypass now running!</font></b></center>")
//	//} else {
//	//	httpProxyStat.SetText("<center><b><font color=reb>http proxy is not running!</font></b></center>")
//	//}
//	//httpProxyStat.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0), core.NewQPoint2(490, 30)))
//
//	autoStartSsr := widgets.NewQCheckBox2("auto Start ssr", settingWindow)
//	autoStartSsr.SetChecked(settingConfig.AutoStartSsr)
//	autoStartSsr.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0),
//		core.NewQPoint2(490, 30)))
//
//	httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", settingWindow)
//	httpProxyCheckBox.SetChecked(settingConfig.HttpProxy)
//	httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40),
//		core.NewQPoint2(130, 70)))
//
//	socks5BypassCheckBox := widgets.NewQCheckBox2("socks5 bypass",
//		settingWindow)
//	socks5BypassCheckBox.SetChecked(settingConfig.Socks5WithBypass)
//	socks5BypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(140, 40),
//		core.NewQPoint2(290, 70)))
//
//	httpBypassCheckBox := widgets.NewQCheckBox2("http bypass", settingWindow)
//	httpBypassCheckBox.SetChecked(settingConfig.HttpWithBypass)
//	httpBypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 40),
//		core.NewQPoint2(450, 70)))
//
//	localAddressLabel := widgets.NewQLabel2("address", settingWindow, 0)
//	localAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80),
//		core.NewQPoint2(80, 110)))
//	localAddressLineText := widgets.NewQLineEdit(settingWindow)
//	localAddressLineText.SetText(settingConfig.LocalAddress)
//	localAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(90, 80),
//		core.NewQPoint2(200, 110)))
//
//	localPortLabel := widgets.NewQLabel2("port", settingWindow, 0)
//	localPortLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 80),
//		core.NewQPoint2(300, 110)))
//	localPortLineText := widgets.NewQLineEdit(settingWindow)
//	localPortLineText.SetText(settingConfig.LocalPort)
//	localPortLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 80),
//		core.NewQPoint2(420, 110)))
//
//	httpAddressLabel := widgets.NewQLabel2("http", settingWindow, 0)
//	httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120),
//		core.NewQPoint2(70, 150)))
//	httpAddressLineText := widgets.NewQLineEdit(settingWindow)
//	httpAddressLineText.SetText(settingConfig.HttpProxyAddressAndPort)
//	httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120),
//		core.NewQPoint2(210, 150)))
//
//	socks5BypassAddressLabel := widgets.NewQLabel2("socks5Bp",
//		settingWindow, 0)
//	socks5BypassAddressLabel.SetGeometry(core.
//		NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
//	socks5BypassLineText := widgets.NewQLineEdit(settingWindow)
//	socks5BypassLineText.SetText(settingConfig.Socks5WithBypassAddressAndPort)
//	socks5BypassLineText.SetGeometry(core.NewQRect2(core.
//		NewQPoint2(300, 120), core.NewQPoint2(420, 150)))
//
//	pythonPathLabel := widgets.NewQLabel2("pythonPath", settingWindow, 0)
//	pythonPathLabel.SetGeometry(core.NewQRect2(core.
//		NewQPoint2(10, 160), core.NewQPoint2(100, 190)))
//	pythonPathLineText := widgets.NewQLineEdit(settingWindow)
//	pythonPathLineText.SetText(settingConfig.PythonPath)
//	pythonPathLineText.SetGeometry(core.NewQRect2(core.
//		NewQPoint2(110, 160), core.NewQPoint2(420, 190)))
//
//	ssrPathLabel := widgets.NewQLabel2("ssrPath", settingWindow, 0)
//	ssrPathLabel.SetGeometry(core.NewQRect2(core.
//		NewQPoint2(10, 200), core.NewQPoint2(100, 230)))
//	ssrPathLineText := widgets.NewQLineEdit(settingWindow)
//	ssrPathLineText.SetText(settingConfig.SsrPath)
//	ssrPathLineText.SetGeometry(core.NewQRect2(core.
//		NewQPoint2(110, 200), core.NewQPoint2(420, 230)))
//
//	BypassFileLabel := widgets.NewQLabel2("ssrPath", settingWindow, 0)
//	BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240),
//		core.NewQPoint2(100, 270)))
//	BypassFileLineText := widgets.NewQLineEdit(settingWindow)
//	BypassFileLineText.SetText(settingConfig.BypassFile)
//	BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 240),
//		core.NewQPoint2(420, 270)))
//
//	applyButton := widgets.NewQPushButton2("apply", settingWindow)
//	applyButton.ConnectClicked(func(bool2 bool) {
//		settingConfig.AutoStartSsr = autoStartSsr.IsChecked()
//		settingConfig.HttpProxy = httpProxyCheckBox.IsChecked()
//		settingConfig.Socks5WithBypass = socks5BypassCheckBox.IsChecked()
//		settingConfig.HttpWithBypass = httpBypassCheckBox.IsChecked()
//		settingConfig.LocalAddress = localAddressLineText.Text()
//		settingConfig.LocalPort = localPortLineText.Text()
//		settingConfig.PythonPath = pythonPathLineText.Text()
//		settingConfig.SsrPath = ssrPathLineText.Text()
//		settingConfig.BypassFile = BypassFileLineText.Text()
//
//		if err = configjson.SettingEnCodeJSON(configPath, settingConfig); err != nil {
//			//log.Println(err)
//			messageBox(err.Error())
//		}
//
//		if httpAddressLineText.Text() !=
//			settingConfig.HttpProxyAddressAndPort || settingConfig.HttpProxy !=
//			httpProxyCheckBox.IsChecked() || settingConfig.HttpWithBypass !=
//			httpBypassCheckBox.IsChecked() {
//			settingConfig.HttpProxyAddressAndPort = httpAddressLineText.Text()
//			if settingConfig.HttpProxy == true &&
//				settingConfig.HttpWithBypass == true {
//				if httpBypass.Process != nil {
//					if err = httpBypass.Process.Kill(); err != nil {
//						//log.Println(err)
//						messageBox(err.Error())
//					}
//					if _, err = httpBypass.Process.Wait(); err != nil {
//						messageBox(err.Error())
//					}
//				}
//			} else if settingConfig.HttpProxy == true {
//				if http.Process != nil {
//					if err = http.Process.Kill(); err != nil {
//						//log.Println(err)
//						messageBox(err.Error())
//					}
//
//					if _, err = http.Process.Wait(); err != nil {
//						messageBox(err.Error())
//					}
//				}
//			}
//			settingConfig.HttpProxy = httpProxyCheckBox.IsChecked()
//			settingConfig.HttpWithBypass = httpBypassCheckBox.IsChecked()
//
//			if err = configjson.SettingEnCodeJSON(configPath, settingConfig); err != nil {
//				//log.Println(err)
//				messageBox(err.Error())
//			}
//			if settingConfig.HttpProxy == true &&
//				settingConfig.HttpWithBypass == true {
//				httpBypass, err = getdelay.GetHttpProxyBypassCmd()
//				if err != nil {
//					messageBox(err.Error())
//				}
//				if err = httpBypass.Start(); err != nil {
//					messageBox(err.Error())
//				}
//			} else if settingConfig.HttpProxy == true {
//				http, err = getdelay.GetHttpProxyCmd()
//				if err != nil {
//					messageBox(err.Error())
//				}
//
//				if err = http.Start(); err != nil {
//					messageBox(err.Error())
//				}
//			}
//		}
//		if settingConfig.Socks5WithBypassAddressAndPort !=
//			socks5BypassLineText.Text() || settingConfig.Socks5WithBypass !=
//			socks5BypassCheckBox.IsChecked() {
//			settingConfig.Socks5WithBypass = socks5BypassCheckBox.IsChecked()
//			settingConfig.Socks5WithBypassAddressAndPort =
//				socks5BypassLineText.Text()
//			if err = configjson.SettingEnCodeJSON(configPath, settingConfig); err != nil {
//				//log.Println(err)
//				messageBox(err.Error())
//			}
//			if socks5Bypass.Process != nil {
//				if err = socks5Bypass.Process.Kill(); err != nil {
//					//log.Println(err)
//					messageBox(err.Error())
//				}
//				if _, err = socks5Bypass.Process.Wait(); err != nil {
//					messageBox(err.Error())
//				}
//			}
//			socks5Bypass, err = getdelay.GetSocks5ProxyBypassCmd()
//			if err != nil {
//				messageBox(err.Error())
//			}
//			if err = socks5Bypass.Start(); err != nil {
//				messageBox(err.Error())
//			}
//		}
//		//else {
//		//	httpProxyCheckBox.SetChecked(settingConfig.HttpProxy)
//		//	socks5BypassCheckBox.SetChecked(settingConfig.Socks5WithBypass)
//		//	httpBypassCheckBox.SetChecked(settingConfig.HttpWithBypass)
//		//	localAddressLineText.SetText(settingConfig.LocalAddress)
//		//	localPortLineText.SetText(settingConfig.LocalPort)
//		//	httpAddressLineText.SetText(settingConfig.HttpProxyAddressAndPort)
//		//	pythonPathLineText.SetText(settingConfig.PythonPath)
//		//	ssrPathLineText.SetText(settingConfig.SsrPath)
//		//	BypassFileLineText.SetText(settingConfig.BypassFile)
//		//}
//	})
//	applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280),
//		core.NewQPoint2(90, 310)))
//
//	settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
//		settingWindow.Close()
//	})
//	return settingWindow, nil
//}
