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
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func SSRSub(configPath string) {
	httpCmd, err := getdelay.GetHttpProxyCmd()
	if err != nil {
		log.Println(err)
	}
	httpBypassCmd, err := getdelay.GetHttpProxyBypassCmd()
	if err != nil {
		log.Println(err)
	}
	socks5BypassCmd, err := getdelay.GetSocks5ProxyBypassCmd()
	if err != nil {
		log.Println(err)
	}
	setting, err := configJSON.SettingDecodeJSON(configPath)
	if err != nil {
		log.Println(err)
	}
	if setting.HttpProxy == true && setting.HttpWithBypass == true {
		err = httpBypassCmd.Start()
		if err != nil {
			log.Println(err)
		}
	} else if setting.HttpProxy == true {
		err = httpCmd.Start()
		if err != nil {
			log.Println(err)
		}
	}
	if setting.Socks5WithBypass == true {
		err = socks5BypassCmd.Start()
		if err != nil {
			log.Println(err)
		}
	}
	window := widgets.NewQMainWindow(nil, 0)
	//window.SetMinimumSize2(600, 400)
	window.SetFixedSize2(600, 400)
	window.SetWindowTitle("SsrMicroClient")
	window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		//closeMessageBox := widgets.NewQMessageBox(window)
		//closeMessageBox.SetWindowTitle("close?")
		//closeMessageBox.SetText("which are you want to do?")
		//closeMessageBox.SetStandardButtons(0x00100000 | 0x00004000 | 0x00000400 | 0x00400000)
		//closeMessageBox.Button(0x00004000).SetText("exit(ssr daemon)")
		//closeMessageBox.Button(0x00000400).SetText("exit")
		//closeMessageBox.Button(0x00100000).SetText("run in background")
		//closeMessageBox.SetDefaultButton2(0x00100000)
		//if closeMessageBoxExec := closeMessageBox.Exec(); closeMessageBoxExec == 0x00004000 {
		//	os.Exit(0)
		//} else if closeMessageBoxExec == 0x00000400 {
		//} else if closeMessageBoxExec == 0x00100000 {
		//	window.Hide()
		//}
		window.Hide()
	})
	icon := gui.NewQIcon5(configPath + "/SsrMicroClient.png")
	window.SetWindowIcon(icon)

	subWindow := subUI(configPath, window)
	settingWindow := SsrMicroClientSetting(window, httpCmd, httpBypassCmd, socks5BypassCmd, configPath)

	trayIcon := widgets.NewQSystemTrayIcon(window)
	trayIcon.SetIcon(icon)
	menu := widgets.NewQMenu(nil)
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

	settingTrayIconMenu := widgets.NewQAction2("setting", window)
	settingTrayIconMenu.ConnectTriggered(func(bool2 bool) {
		if settingWindow.IsHidden() == false {
			settingWindow.Close()
		}
		settingWindow.Show()
	})

	exit := widgets.NewQAction2("exit", window)
	exit.ConnectTriggered(func(bool2 bool) {
		if httpBypassCmd.Process != nil {
			err = httpBypassCmd.Process.Kill()
			if err != nil {
				//	do something
			}
			err = httpBypassCmd.Wait()
			if err != nil {
				//	do something
			}
		}
		if httpCmd.Process != nil {
			err = httpCmd.Process.Kill()
			if err != nil {
				//	do something
			}
			err = httpCmd.Wait()
			if err != nil {
				//	do something
			}
		}
		if socks5BypassCmd.Process != nil {
			err = socks5BypassCmd.Process.Kill()
			if err != nil {
				//
			}
			err = socks5BypassCmd.Wait()
			if err != nil {
				//
			}
		}
		os.Exit(0)
	})
	actions := []*widgets.QAction{ssrMicroClientTrayIconMenu, subscriptionTrayIconMenu, settingTrayIconMenu, exit}
	menu.AddActions(actions)
	trayIcon.SetContextMenu(menu)
	updateStatus := func() string {
		var status string
		if pid, run := process.Get(configPath); run == true {
			status = "<b><font color=green>running (pid: " + pid + ")</font></b>"
		} else {
			status = "<b><font color=reb>stopped</font></b>"
		}
		return status
	}
	trayIcon.SetToolTip(updateStatus())
	trayIcon.Show()

	statusLabel := widgets.NewQLabel2("status", window, core.Qt__WindowType(0x00000000))
	statusLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 10), core.NewQPoint2(130, 40)))
	statusLabel2 := widgets.NewQLabel2(updateStatus(), window, core.Qt__WindowType(0x00000000))
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
			trayIcon.SetToolTip(updateStatus())
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
				time.Sleep(250 * time.Millisecond)
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
			trayIcon.SetToolTip(updateStatus())
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
			delayString = "delay > 3s or server can not connect"
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

	subUpdateButton := widgets.NewQPushButton2("subscription Update", window)
	subUpdateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 260), core.NewQPoint2(560, 290)))
	subUpdateButton.ConnectClicked(func(bool2 bool) {
		message := widgets.NewQMessageBox(window)
		message.SetText("Updating!")
		message.Show()
		if err := configJSON.SsrJSON(configPath); err != nil {
			log.Println(err)
		}
		message.SetText("Updated!")
		group, err = configJSON.GetGroup(configPath)
		if err != nil {
			log.Println(err)
			return
		}
		groupCombobox.Clear()
		groupCombobox.AddItems(group)
		groupCombobox.SetCurrentText(nowNode["group"])
		node, err = configJSON.GetNode(configPath, groupCombobox.CurrentText())
		if err != nil {
			log.Println(err)
			return
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)
		nodeCombobox.SetCurrentText(nowNode["remarks"])

	})
	window.Show()
}

func subUI(configPath string, parent *widgets.QMainWindow) *widgets.QMainWindow {
	subWindow := widgets.NewQMainWindow(parent, 0)
	subWindow.SetFixedSize2(700, 100)
	subWindow.SetWindowTitle("subscription")
	subWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		subWindow.Hide()
	})

	subLabel := widgets.NewQLabel2("subscription", subWindow, core.Qt__WindowType(0x00000000))
	subLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 10), core.NewQPoint2(130, 40)))
	subCombobox := widgets.NewQComboBox(subWindow)
	var link []string
	subRefresh := func() {
		subCombobox.Clear()
		var err error
		link, err = configJSON.GetLink(configPath)
		if err != nil {
			log.Println(err)
		}
		subCombobox.AddItems(link)
	}
	subRefresh()
	subCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 10), core.NewQPoint2(600, 40)))

	deleteButton := widgets.NewQPushButton2("delete", subWindow)
	deleteButton.ConnectClicked(func(bool2 bool) {
		linkToDelete := subCombobox.CurrentText()
		if err := configJSON.RemoveLinkJSON2(linkToDelete, configPath); err != nil {
			log.Println(err)
		}
		subRefresh()
	})
	deleteButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 10), core.NewQPoint2(690, 40)))

	lineText := widgets.NewQLineEdit(subWindow)
	lineText.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 50), core.NewQPoint2(600, 80)))

	addButton := widgets.NewQPushButton2("add", subWindow)
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
		if err := configJSON.AddLinkJSON2(linkToAdd, configPath); err != nil {
			log.Println(err)
			return
		}
		subRefresh()
	})
	addButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 50), core.NewQPoint2(690, 80)))
	//updateButton := widgets.NewQPushButton2("update",subWindow)
	//updateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(200,450),core.NewQPoint2(370,490)))
	return subWindow
}

func SsrMicroClientSetting(parent *widgets.QMainWindow, http, httpBypass, socks5Bypass *exec.Cmd, configPath string) *widgets.QMainWindow {
	settingConfig, err := configJSON.SettingDecodeJSON(configPath)
	if err != nil {
		log.Println(err)
	}
	settingWindow := widgets.NewQMainWindow(parent, 0)
	settingWindow.SetFixedSize2(430, 330)
	settingWindow.SetWindowTitle("setting")
	settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		settingWindow.Hide()
	})

	//httpProxyStat := widgets.NewQLabel(settingWindow, 0)
	//if http.ProcessState != nil {
	//	httpProxyStat.SetText("<center><b><font color=green>http proxy now running!</font></b></center>")
	//} else if httpBypass.ProcessState != nil {
	//	httpProxyStat.SetText("<center><b><font color=green>http proxy with bypass now running!</font></b></center>")
	//} else {
	//	httpProxyStat.SetText("<center><b><font color=reb>http proxy is not running!</font></b></center>")
	//}
	//httpProxyStat.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0), core.NewQPoint2(490, 30)))

	httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", settingWindow)
	httpProxyCheckBox.SetChecked(settingConfig.HttpProxy)
	httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40), core.NewQPoint2(130, 70)))

	socks5BypassCheckBox := widgets.NewQCheckBox2("socks5 bypass", settingWindow)
	socks5BypassCheckBox.SetChecked(settingConfig.Socks5WithBypass)
	socks5BypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(140, 40), core.NewQPoint2(290, 70)))

	httpBypassCheckBox := widgets.NewQCheckBox2("http bypass", settingWindow)
	httpBypassCheckBox.SetChecked(settingConfig.HttpWithBypass)
	httpBypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 40), core.NewQPoint2(450, 70)))

	localAddressLabel := widgets.NewQLabel2("address", settingWindow, 0)
	localAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80), core.NewQPoint2(80, 110)))
	localAddressLineText := widgets.NewQLineEdit(settingWindow)
	localAddressLineText.SetText(settingConfig.LocalAddress)
	localAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(90, 80), core.NewQPoint2(200, 110)))

	localPortLabel := widgets.NewQLabel2("port", settingWindow, 0)
	localPortLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 80), core.NewQPoint2(300, 110)))
	localPortLineText := widgets.NewQLineEdit(settingWindow)
	localPortLineText.SetText(settingConfig.LocalPort)
	localPortLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 80), core.NewQPoint2(420, 110)))

	httpAddressLabel := widgets.NewQLabel2("http", settingWindow, 0)
	httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120), core.NewQPoint2(70, 150)))
	httpAddressLineText := widgets.NewQLineEdit(settingWindow)
	httpAddressLineText.SetText(settingConfig.HttpProxyAddressAndPort)
	httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120), core.NewQPoint2(210, 150)))

	socks5BypassAddressLabel := widgets.NewQLabel2("socks5Bp", settingWindow, 0)
	socks5BypassAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
	socks5BypassLineText := widgets.NewQLineEdit(settingWindow)
	socks5BypassLineText.SetText(settingConfig.Socks5WithBypassAddressAndPort)
	socks5BypassLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 120), core.NewQPoint2(420, 150)))

	pythonPathLabel := widgets.NewQLabel2("pythonPath", settingWindow, 0)
	pythonPathLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 160), core.NewQPoint2(100, 190)))
	pythonPathLineText := widgets.NewQLineEdit(settingWindow)
	pythonPathLineText.SetText(settingConfig.PythonPath)
	pythonPathLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 160), core.NewQPoint2(420, 190)))

	ssrPathLabel := widgets.NewQLabel2("ssrPath", settingWindow, 0)
	ssrPathLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 200), core.NewQPoint2(100, 230)))
	ssrPathLineText := widgets.NewQLineEdit(settingWindow)
	ssrPathLineText.SetText(settingConfig.SsrPath)
	ssrPathLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 200), core.NewQPoint2(420, 230)))

	BypassFileLabel := widgets.NewQLabel2("ssrPath", settingWindow, 0)
	BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240), core.NewQPoint2(100, 270)))
	BypassFileLineText := widgets.NewQLineEdit(settingWindow)
	BypassFileLineText.SetText(settingConfig.BypassFile)
	BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 240), core.NewQPoint2(420, 270)))

	applyButton := widgets.NewQPushButton2("apply", settingWindow)
	applyButton.ConnectClicked(func(bool2 bool) {
		settingConfig.HttpProxy = httpProxyCheckBox.IsChecked()
		settingConfig.Socks5WithBypass = socks5BypassCheckBox.IsChecked()
		settingConfig.HttpWithBypass = httpBypassCheckBox.IsChecked()
		settingConfig.LocalAddress = localAddressLineText.Text()
		settingConfig.LocalPort = localPortLineText.Text()
		settingConfig.PythonPath = pythonPathLineText.Text()
		settingConfig.SsrPath = ssrPathLineText.Text()
		settingConfig.BypassFile = BypassFileLineText.Text()
		err = configJSON.SettingEnCodeJSON(configPath, settingConfig)
		if err != nil {
			log.Println(err)
		}

		if httpAddressLineText.Text() != settingConfig.HttpProxyAddressAndPort ||
			settingConfig.HttpProxy != httpProxyCheckBox.IsChecked() ||
			settingConfig.HttpWithBypass != httpBypassCheckBox.IsChecked() {
			settingConfig.HttpProxyAddressAndPort = httpAddressLineText.Text()
			if settingConfig.HttpProxy == true && settingConfig.HttpWithBypass == true {
				if httpBypass.Process != nil {
					err = httpBypass.Process.Kill()
					if err != nil {
						log.Println(err)
					}
					_ = httpBypass.Wait()
				}
			} else if settingConfig.HttpProxy == true {
				if http.Process != nil {
					err = http.Process.Kill()
					if err != nil {
						log.Println(err)
					}
					_ = http.Wait()
				}
			}
			settingConfig.HttpProxy = httpProxyCheckBox.IsChecked()
			settingConfig.HttpWithBypass = httpBypassCheckBox.IsChecked()
			err = configJSON.SettingEnCodeJSON(configPath, settingConfig)
			if err != nil {
				log.Println(err)
			}
			if settingConfig.HttpProxy == true && settingConfig.HttpWithBypass == true {
				httpBypass, _ = getdelay.GetHttpProxyBypassCmd()
				_ = httpBypass.Start()
			} else if settingConfig.HttpProxy == true {
				http, _ = getdelay.GetHttpProxyCmd()
				_ = http.Start()
			}
		}
		if settingConfig.Socks5WithBypassAddressAndPort != socks5BypassLineText.Text() ||
			settingConfig.Socks5WithBypass != socks5BypassCheckBox.IsChecked() {
			settingConfig.Socks5WithBypass = socks5BypassCheckBox.IsChecked()
			settingConfig.Socks5WithBypassAddressAndPort = socks5BypassLineText.Text()
			err = configJSON.SettingEnCodeJSON(configPath, settingConfig)
			if err != nil {
				log.Println(err)
			}
			if socks5Bypass.Process != nil {
				err = socks5Bypass.Process.Kill()
				if err != nil {
					log.Println(err)
				}
				_ = socks5Bypass.Wait()
			}
			socks5Bypass, _ = getdelay.GetSocks5ProxyBypassCmd()
			_ = socks5Bypass.Start()
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
	applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280), core.NewQPoint2(90, 310)))
	return settingWindow
}

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
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
		} else if *subDaemon == "socks5Bp" {
			getdelay.StartSocks5Bypass(configPath)
		} else if *subDaemon == "httpBBp" {
			getdelay.StartHTTPByArgumentBypass()
		}
	} else {
		app := widgets.NewQApplication(len(os.Args), os.Args)
		app.SetApplicationName("SsrMicroClient")
		pid, isExist := process.GetProcessStatus(configPath + "/SsrMicroClient.pid")
		if isExist == true {
			message := widgets.NewQMessageBox(nil)
			message.SetText("process is exist at pid = " + pid + "!")
			message.Exec()
			return
		} else {
			_ = ioutil.WriteFile(configPath+"/SsrMicroClient.pid", []byte(strconv.Itoa(os.Getpid())), 0644)
			SSRSub(configPath)
			app.Exec()
		}
	}
}
