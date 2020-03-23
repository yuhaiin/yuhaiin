package gui

import (
	"github.com/Asutorufa/SsrMicroClient/process/control"
	"github.com/therecipe/qt/widgets"
	"os"
)

type SsrMicroClientGUI struct {
	App                *widgets.QApplication
	MainWindow         *widgets.QMainWindow
	subscriptionWindow *widgets.QMainWindow
	settingWindow      *widgets.QMainWindow
	control            *ServerControl.Control
}

func NewSsrMicroClientGUI() (*SsrMicroClientGUI, error) {
	var err error
	microClientGUI := &SsrMicroClientGUI{}
	microClientGUI.App = widgets.NewQApplication(len(os.Args), os.Args)
	microClientGUI.App.SetApplicationName("SsrMicroClient")
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

func (ssrMicroClientGUI *SsrMicroClientGUI) openMainWindow() {
	if ssrMicroClientGUI.MainWindow.IsHidden() == false {
		ssrMicroClientGUI.MainWindow.Hide()
	}
	ssrMicroClientGUI.MainWindow.Move2((ssrMicroClientGUI.App.Desktop().Width()-ssrMicroClientGUI.MainWindow.Width())/2, (ssrMicroClientGUI.App.Desktop().Height()-ssrMicroClientGUI.MainWindow.Height())/2)
	ssrMicroClientGUI.MainWindow.Show()
}

func (ssrMicroClientGUI *SsrMicroClientGUI) openSubscriptionWindow() {
	if ssrMicroClientGUI.subscriptionWindow.IsHidden() == false {
		ssrMicroClientGUI.subscriptionWindow.Close()
	}

	ssrMicroClientGUI.subscriptionWindow.Move2((ssrMicroClientGUI.App.Desktop().Width()-ssrMicroClientGUI.subscriptionWindow.Width())/2, (ssrMicroClientGUI.App.Desktop().Height()-ssrMicroClientGUI.subscriptionWindow.Height())/2)
	ssrMicroClientGUI.subscriptionWindow.Show()
}

func (ssrMicroClientGUI *SsrMicroClientGUI) openSettingWindow() {
	if ssrMicroClientGUI.settingWindow.IsHidden() == false {
		ssrMicroClientGUI.settingWindow.Close()
	}
	ssrMicroClientGUI.settingWindow.Move2((ssrMicroClientGUI.App.Desktop().Width()-ssrMicroClientGUI.settingWindow.Width())/2, (ssrMicroClientGUI.App.Desktop().Height()-ssrMicroClientGUI.settingWindow.Height())/2)
	ssrMicroClientGUI.settingWindow.Show()
}

func (ssrMicroClientGUI *SsrMicroClientGUI) MessageBox(text string) {
	message := widgets.NewQMessageBox(nil)
	message.SetText(text)
	message.Exec()
}
