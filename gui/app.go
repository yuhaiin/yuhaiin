package gui

import (
	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/Asutorufa/SsrMicroClient/process/ServerControl"
	"github.com/Asutorufa/SsrMicroClient/process/ssrcontrol"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
	"log"
	"os"
	"os/exec"
)

type SsrMicroClientGUI struct {
	App                *widgets.QApplication
	MainWindow         *widgets.QMainWindow
	subscriptionWindow *widgets.QMainWindow
	settingWindow      *widgets.QMainWindow
	Session            *gui.QSessionManager
	ssrCmd             *exec.Cmd
	configPath         string
	settingConfig      *config.Setting
	server             *ServerControl.ServerControl
}

func NewSsrMicroClientGUI(configPath string) (*SsrMicroClientGUI, error) {
	var err error
	microClientGUI := &SsrMicroClientGUI{}
	microClientGUI.configPath = configPath
	microClientGUI.settingConfig, err = config.SettingDecodeJSON(microClientGUI.configPath)
	if err != nil {
		return microClientGUI, err
	}
	microClientGUI.ssrCmd = ssrcontrol.GetSsrCmd(microClientGUI.configPath)
	microClientGUI.App = widgets.NewQApplication(len(os.Args), os.Args)
	microClientGUI.App.SetApplicationName("SsrMicroClient")
	microClientGUI.App.SetQuitOnLastWindowClosed(false)
	microClientGUI.App.ConnectAboutToQuit(func() {
		if microClientGUI.ssrCmd.Process != nil {
			err = microClientGUI.ssrCmd.Process.Kill()
			if err != nil {
				//	do something
				log.Println(err)
			}
			_, err = microClientGUI.ssrCmd.Process.Wait()
			if err != nil {
				//	do something
				log.Println(err)
			}
		}
	})

	microClientGUI.server = &ServerControl.ServerControl{}

	microClientGUI.Session = gui.NewQSessionManagerFromPointer(nil)
	microClientGUI.App.SaveStateRequest(microClientGUI.Session)
	microClientGUI.createMainWindow()
	microClientGUI.createSubscriptionWindow()
	microClientGUI.createSettingWindow()

	if microClientGUI.settingConfig.Bypass == true {
		microClientGUI.server.ServerStart()
	}

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
