package gui

import (
	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/Asutorufa/SsrMicroClient/net/delay"
	"github.com/Asutorufa/SsrMicroClient/subscr"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

var (
	iconPath = config.GetConfigAndSQLPath() + "/SsrMicroClient.png"
)

func (ssrMicroClientGUI *SsrMicroClientGUI) createMainWindow() {
	ssrMicroClientGUI.MainWindow = widgets.NewQMainWindow(nil, 0)
	ssrMicroClientGUI.MainWindow.SetFixedSize2(600, 400)
	ssrMicroClientGUI.MainWindow.SetWindowTitle("SsrMicroClient")
	icon := gui.NewQIcon5(iconPath)
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

	statusLabel := widgets.NewQLabel2("status", ssrMicroClientGUI.MainWindow, core.Qt__WindowType(0x00000000))
	statusLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 10), core.NewQPoint2(130, 40)))
	statusLabel2 := widgets.NewQLabel2("", ssrMicroClientGUI.MainWindow, core.Qt__WindowType(0x00000000))
	statusLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 10), core.NewQPoint2(560, 40)))

	nowNodeLabel := widgets.NewQLabel2("now node", ssrMicroClientGUI.MainWindow, core.Qt__WindowType(0x00000000))
	nowNodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 60), core.NewQPoint2(130, 90)))
	nowNodeName, nowNodeGroup := subscr.GetNowNodeGroupAndName()
	nowNodeLabel2 := widgets.NewQLabel2(nowNodeName+" - "+nowNodeGroup, ssrMicroClientGUI.MainWindow, core.Qt__WindowType(0x00000000))
	nowNodeLabel2.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 60), core.NewQPoint2(560, 90)))

	groupLabel := widgets.NewQLabel2("group", ssrMicroClientGUI.MainWindow, core.Qt__WindowType(0x00000000))
	groupLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 110), core.NewQPoint2(130, 140)))
	groupCombobox := widgets.NewQComboBox(ssrMicroClientGUI.MainWindow)
	group, err := subscr.GetGroup()
	if err != nil {
		ssrMicroClientGUI.MessageBox(err.Error())
		return
	}
	groupCombobox.AddItems(group)
	groupCombobox.SetCurrentTextDefault(nowNodeGroup)
	groupCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 110), core.NewQPoint2(450, 140)))
	refreshButton := widgets.NewQPushButton2("refresh", ssrMicroClientGUI.MainWindow)
	refreshButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 110), core.NewQPoint2(560, 140)))

	nodeLabel := widgets.NewQLabel2("node", ssrMicroClientGUI.MainWindow, core.Qt__WindowType(0x00000000))
	nodeLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 160), core.NewQPoint2(130, 190)))
	nodeCombobox := widgets.NewQComboBox(ssrMicroClientGUI.MainWindow)
	node, err := subscr.GetNode(groupCombobox.CurrentText())
	if err != nil {
		ssrMicroClientGUI.MessageBox(err.Error())
		return
	}
	nodeCombobox.AddItems(node)
	nodeCombobox.SetCurrentTextDefault(nowNodeName)
	nodeCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(130, 160), core.NewQPoint2(450, 190)))
	startButton := widgets.NewQPushButton2("start", ssrMicroClientGUI.MainWindow)
	startButton.ConnectClicked(func(bool2 bool) {

		group := groupCombobox.CurrentText()
		remarks := nodeCombobox.CurrentText()
		if err := subscr.ChangeNowNode(group, remarks); err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}
		if err := ssrMicroClientGUI.control.ChangeNode(); err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}
		nowNodeLabel2.SetText(remarks + " - " + group)
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
			server, port := subscr.GetOneNodeAddress(group, remarks)
			delayTmp, isSuccess, err := delay.TCPDelay(server, port)
			var delayString string
			if err != nil {
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
	delayButton.SetGeometry(core.NewQRect2(core.NewQPoint2(460, 210), core.NewQPoint2(560, 240)))

	groupCombobox.ConnectCurrentTextChanged(func(string2 string) {
		node, err := subscr.GetNode(groupCombobox.CurrentText())
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)
	})

	subButton := widgets.NewQPushButton2("subscription setting", ssrMicroClientGUI.MainWindow)
	subButton.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 260), core.NewQPoint2(290, 290)))
	subButton.ConnectClicked(func(bool2 bool) {
		ssrMicroClientGUI.openSubscriptionWindow()
	})

	subUpdateButton := widgets.NewQPushButton2("subscription Update", ssrMicroClientGUI.MainWindow)
	subUpdateButton.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 260), core.NewQPoint2(560, 290)))
	subUpdateButton.ConnectClicked(func(bool2 bool) {
		message := widgets.NewQMessageBox(ssrMicroClientGUI.MainWindow)
		message.SetText("Updating!")
		message.Show()
		if err := subscr.GetLinkFromInt(); err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}
		message.SetText("Updated!")

		group, err := subscr.GetGroup()
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}
		groupCombobox.Clear()
		groupCombobox.AddItems(group)
		node, err := subscr.GetNode(groupCombobox.CurrentText())
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}
		nodeCombobox.Clear()
		nodeCombobox.AddItems(node)

		nowNodeName, nowNodeGroup := subscr.GetNowNodeGroupAndName()
		groupCombobox.SetCurrentText(nowNodeGroup)
		nodeCombobox.SetCurrentText(nowNodeName)
	})

	settingButton := widgets.NewQPushButton2("Setting", ssrMicroClientGUI.MainWindow)
	settingButton.SetGeometry(core.NewQRect2(core.NewQPoint2(40, 300), core.NewQPoint2(290, 330)))
	settingButton.ConnectClicked(func(bool2 bool) {
		ssrMicroClientGUI.openSettingWindow()
	})
}
