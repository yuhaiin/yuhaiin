package gui

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/api"
	cloud512 "github.com/Asutorufa/yuhaiin/gui/icon"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

var (
	apiC       api.ApiClient
	App        = widgets.NewQApplication(len(os.Args), os.Args)
	messageBox = widgets.NewQMessageBox(nil)
)

type SGui struct {
	App       *widgets.QApplication
	main      *mainWindow
	subscribe *subscribe
	setting   *setting
	trayIcon  *widgets.QSystemTrayIcon
}

func NewGui(client api.ApiClient) *SGui {
	apiC = client
	microClientGUI := &SGui{}
	microClientGUI.App = App
	microClientGUI.App.SetApplicationName("yuhaiin")
	microClientGUI.App.SetQuitOnLastWindowClosed(false)
	microClientGUI.main = NewMain()
	microClientGUI.subscribe = NewSubscribe()
	microClientGUI.setting = NewSetting()

	microClientGUI.main.setMenuBar(microClientGUI.menuBar())
	microClientGUI.trayInit()
	go func() { _ = microClientGUI.clientInit() }()
	return microClientGUI
}

func (sGui *SGui) menuBar() *widgets.QMenuBar {
	menuBar := widgets.NewQMenuBar(sGui.main.window)
	menuBar.SetFixedWidth(sGui.main.window.Width())
	mainMenu := menuBar.AddMenu2("Yuhaiin")
	settingMenu := mainMenu.AddAction("Settings...")
	settingMenu.ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.setting.window) })
	exitMenu := mainMenu.AddAction("Exit")
	exitMenu.ConnectTriggered(func(checked bool) { sGui.App.Quit() })
	subMenuGroup := menuBar.AddMenu2("Subscribe")
	subUpdate := subMenuGroup.AddAction("Update")
	subUpdate.ConnectTriggered(func(checked bool) { sGui.main.subUpdate() })
	subSetting := subMenuGroup.AddAction("Edit")
	subSetting.ConnectTriggered(func(checked bool) { sGui.openWindow(sGui.subscribe.window) })
	aboutMenu := menuBar.AddMenu2("About")
	githubAbout := aboutMenu.AddAction("Github")
	githubAbout.ConnectTriggered(func(checked bool) {
		gui.QDesktopServices_OpenUrl(core.NewQUrl3("https://github.com/Asutorufa/yuhaiin", core.QUrl__TolerantMode))
	})
	authorAbout := aboutMenu.AddAction("Author: Asutorufa")
	authorAbout.ConnectTriggered(func(checked bool) {
		gui.QDesktopServices_OpenUrl(core.NewQUrl3("https://github.com/Asutorufa", core.QUrl__TolerantMode))
	})
	aboutMenu.AddSeparator()
	aboutMenu.AddAction("Version: 0.2.12 Beta")
	menuBar.AdjustSize()
	return menuBar
}

func (sGui *SGui) clientInit() error {
	c, err := apiC.SingleInstance(context.Background())
	if err != nil {
		return err
	}
	for {
		_, err := c.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		fmt.Println("Open Main Window.")
		sGui.openWindow(sGui.main.window)
	}
	return nil
}

func (sGui *SGui) trayInit() {
	img := gui.NewQPixmap()
	iconData, _ := cloud512.Asset("cloud512.png")
	img.LoadFromData(iconData, uint(len(iconData)), "png", core.Qt__AutoColor)
	icon := gui.NewQIcon2(img)
	sGui.App.SetWindowIcon(icon)

	sGui.trayIcon = widgets.NewQSystemTrayIcon(sGui.App)
	sGui.trayIcon.SetIcon(icon)
	sGui.trayIcon.SetContextMenu(widgets.NewQMenu(nil))
	sGui.trayIcon.ContextMenu().AddAction("Open Yuhaiin").ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.main.window) })
	sGui.trayIcon.ContextMenu().AddAction("Subscribe Setting").ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.subscribe.window) })
	sGui.trayIcon.ContextMenu().AddAction("App Setting").ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.setting.window) })
	sGui.trayIcon.ContextMenu().AddAction("Quit Yuhaiin").ConnectTriggered(func(bool2 bool) { sGui.App.Quit() })
	sGui.trayIcon.ConnectActivated(sGui.trayActivateCall)
	sGui.trayIcon.Show()
}

func (sGui *SGui) openWindow(window *widgets.QMainWindow) {
	if window.IsHidden() {
		window.Move2((sGui.App.Desktop().Width()-window.Width())/2, (sGui.App.Desktop().Height()-window.Height())/2)
		window.Show()
	}
	if window.IsMinimized() {
		window.ShowNormal()
	}
	window.ActivateWindow()
}

func (sGui *SGui) trayActivateCall(reason widgets.QSystemTrayIcon__ActivationReason) {
	switch reason {
	case widgets.QSystemTrayIcon__Trigger:
		if sGui.main.window.IsActiveWindow() {
			sGui.main.window.Hide()
			return
		}
		sGui.openWindow(sGui.main.window)
	}
}

func MessageBox(text string) {
	messageBox.SetText(text)
	messageBox.Exec()
}
