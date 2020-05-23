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
}

func NewGui() *SGui {
	microClientGUI := &SGui{}
	microClientGUI.App = widgets.NewQApplication(len(os.Args), os.Args)
	microClientGUI.App.SetApplicationName("yuhaiin")
	microClientGUI.App.SetQuitOnLastWindowClosed(false)
	microClientGUI.MainWindow = NewMainWindow(nil)
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

	menu := widgets.NewQMenu(nil)
	ssrMicroClientTrayIconMenu := widgets.NewQAction2("Open Yuhaiin", sGui.App)
	ssrMicroClientTrayIconMenu.ConnectTriggered(func(bool2 bool) { sGui.openMainWindow() })
	subscriptionTrayIconMenu := widgets.NewQAction2("Subscribe Setting", sGui.App)
	subscriptionTrayIconMenu.ConnectTriggered(func(bool2 bool) { sGui.openSubscriptionWindow() })
	settingTrayIconMenu := widgets.NewQAction2("App Setting", sGui.App)
	settingTrayIconMenu.ConnectTriggered(func(bool2 bool) { sGui.openSettingWindow() })
	exit := widgets.NewQAction2("Quit Yuhaiin", sGui.App)
	exit.ConnectTriggered(func(bool2 bool) { sGui.App.Quit() })
	menu.AddActions([]*widgets.QAction{ssrMicroClientTrayIconMenu, subscriptionTrayIconMenu, settingTrayIconMenu, exit})

	trayIcon := widgets.NewQSystemTrayIcon(sGui.App)
	trayIcon.SetIcon(icon2)
	trayIcon.SetContextMenu(menu)
	trayIcon.Show()
}

func (sGui *SGui) openMainWindow() {
	if sGui.MainWindow.IsHidden() == false {
		sGui.MainWindow.Hide()
	}
	sGui.MainWindow.Move2((sGui.App.Desktop().Width()-sGui.MainWindow.Width())/2, (sGui.App.Desktop().Height()-sGui.MainWindow.Height())/2)
	sGui.MainWindow.Show()
}

func (sGui *SGui) openSubscriptionWindow() {
	if sGui.subscriptionWindow.IsHidden() == false {
		sGui.subscriptionWindow.Close()
	}

	sGui.subscriptionWindow.Move2((sGui.App.Desktop().Width()-sGui.subscriptionWindow.Width())/2, (sGui.App.Desktop().Height()-sGui.subscriptionWindow.Height())/2)
	sGui.subscriptionWindow.Show()
}

func (sGui *SGui) openSettingWindow() {
	if sGui.settingWindow.IsHidden() == false {
		sGui.settingWindow.Close()
	}
	sGui.settingWindow.Move2((sGui.App.Desktop().Width()-sGui.settingWindow.Width())/2, (sGui.App.Desktop().Height()-sGui.settingWindow.Height())/2)
	sGui.settingWindow.Show()
}

func (sGui *SGui) MessageBox(text string) {
	message := widgets.NewQMessageBox(nil)
	message.SetText(text)
	message.Exec()
}
