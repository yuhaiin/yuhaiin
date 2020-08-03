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
	App        = widgets.NewQApplication(len(os.Args), os.Args)
	messageBox = widgets.NewQMessageBox(nil)
)

type SGui struct {
	App                *widgets.QApplication
	MainWindow         *widgets.QMainWindow
	mainMenuBar        *widgets.QMenuBar
	subscriptionWindow *widgets.QMainWindow
	settingWindow      *widgets.QMainWindow
	trayIcon           *widgets.QSystemTrayIcon
}

func NewGui(client api.ApiClient) *SGui {
	apiC = client
	microClientGUI := &SGui{}
	microClientGUI.App = App
	microClientGUI.App.SetApplicationName("yuhaiin")
	microClientGUI.App.SetQuitOnLastWindowClosed(false)
	microClientGUI.MainWindow = NewMainWindow(microClientGUI)
	microClientGUI.subscriptionWindow = NewSubscription(microClientGUI.MainWindow)
	microClientGUI.settingWindow = NewSettingWindow(microClientGUI.MainWindow)
	microClientGUI.trayInit()
	go func() { _ = microClientGUI.clientInit() }()
	return microClientGUI
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
		sGui.openWindow(sGui.MainWindow)
	}
	return nil
}

func (sGui *SGui) trayInit() {
	img := gui.NewQPixmap()
	iconData, _ := cloud512.Asset("cloud512.png")
	img.LoadFromData(iconData, uint(len(iconData)), "png", core.Qt__AutoColor)
	icon2 := gui.NewQIcon2(img)
	sGui.App.SetWindowIcon(icon2)

	sGui.trayIcon = widgets.NewQSystemTrayIcon(sGui.App)
	sGui.trayIcon.SetIcon(icon2)
	sGui.trayIcon.SetContextMenu(widgets.NewQMenu(nil))
	sGui.trayIcon.ContextMenu().AddAction("Open Yuhaiin").ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.MainWindow) })
	sGui.trayIcon.ContextMenu().AddAction("Subscribe Setting").ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.subscriptionWindow) })
	sGui.trayIcon.ContextMenu().AddAction("App Setting").ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.settingWindow) })
	sGui.trayIcon.ContextMenu().AddAction("Quit Yuhaiin").ConnectTriggered(func(bool2 bool) { sGui.App.Quit() })
	sGui.trayIcon.ConnectActivated(func(reason widgets.QSystemTrayIcon__ActivationReason) {
		switch reason {
		case widgets.QSystemTrayIcon__Trigger:
			if sGui.MainWindow.IsHidden() {
				sGui.openWindow(sGui.MainWindow)
				break
			}
			sGui.MainWindow.Hide()
		}
	})
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

func MessageBox(text string) {
	messageBox.SetText(text)
	messageBox.Exec()
}
