package gui

import (
	"github.com/Asutorufa/yuhaiin/process/control"
	"github.com/therecipe/qt/widgets"
	"os"
)

type SGui struct {
	App                *widgets.QApplication
	MainWindow         *widgets.QMainWindow
	subscriptionWindow *widgets.QMainWindow
	settingWindow      *widgets.QMainWindow
	control            *ServerControl.Control
}

func NewGui() (*SGui, error) {
	var err error
	microClientGUI := &SGui{}
	microClientGUI.App = widgets.NewQApplication(len(os.Args), os.Args)
	microClientGUI.App.SetApplicationName("yuhaiin")
	microClientGUI.App.SetQuitOnLastWindowClosed(false)
	//microClientGUI.App.ConnectAboutToQuit(func() {
	//})
	microClientGUI.control, err = ServerControl.NewControl()
	if err != nil {
		microClientGUI.MessageBox(err.Error())
	}
	microClientGUI.createMainWindow()
	microClientGUI.createSubscriptionWindow()
	microClientGUI.createSettingWindow()

	return microClientGUI, nil
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
