package gui

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
	"os"
)

type SGui struct {
	App                *widgets.QApplication
	MainWindow         *widgets.QMainWindow
	mainMenuBar        *widgets.QMenuBar
	subscriptionWindow *widgets.QMainWindow
	settingWindow      *widgets.QMainWindow
	trayIcon           *widgets.QSystemTrayIcon
}

func NewGui() *SGui {
	microClientGUI := &SGui{}
	microClientGUI.App = widgets.NewQApplication(len(os.Args), os.Args)
	microClientGUI.App.SetApplicationName("yuhaiin")
	microClientGUI.App.SetQuitOnLastWindowClosed(false)
	microClientGUI.MainWindow = NewMainWindow(microClientGUI)
	microClientGUI.subscriptionWindow = NewSubscription(microClientGUI.MainWindow)
	microClientGUI.settingWindow = NewSettingWindow(microClientGUI.MainWindow)
	microClientGUI.trayInit()
	return microClientGUI
}

func (sGui *SGui) trayInit() {
	img := gui.NewQPixmap()
	conFig, err := config.SettingDecodeJSON()
	if err != nil || !conFig.BlackIcon {
		img.LoadFromData2(core.QByteArray_FromBase64(core.NewQByteArray2(iconWhite, len(iconWhite))), "svg", core.Qt__AutoColor)
	} else {
		img.LoadFromData2(core.QByteArray_FromBase64(core.NewQByteArray2(icon, len(icon))), "svg", core.Qt__AutoColor)
	}
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
			} else {
				sGui.MainWindow.Hide()
			}
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
	message := widgets.NewQMessageBox(nil)
	message.SetText(text)
	message.Exec()
}
