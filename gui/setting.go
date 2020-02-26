package gui

import (
	config2 "SsrMicroClient/config"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

func (ssrMicroClientGUI *SsrMicroClientGUI) createSettingWindow() {
	ssrMicroClientGUI.settingWindow = widgets.NewQMainWindow(ssrMicroClientGUI.MainWindow, 0)
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
	httpProxyCheckBox.SetDisabled(true)
	httpProxyCheckBox.SetChecked(ssrMicroClientGUI.settingConfig.HttpProxy)
	httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40),
		core.NewQPoint2(130, 70)))

	bypassCheckBox := widgets.NewQCheckBox2("bypass",
		ssrMicroClientGUI.settingWindow)
	bypassCheckBox.SetDisabled(true)
	bypassCheckBox.SetChecked(ssrMicroClientGUI.settingConfig.Bypass)
	bypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(140, 40),
		core.NewQPoint2(220, 70)))

	DnsOverHttpsCheckBox := widgets.NewQCheckBox2("Use DNSOverHTTPS",
		ssrMicroClientGUI.settingWindow)
	DnsOverHttpsCheckBox.SetChecked(ssrMicroClientGUI.settingConfig.IsDNSOverHTTPS)
	DnsOverHttpsCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 40),
		core.NewQPoint2(450, 70)))

	//httpBypassCheckBox := widgets.NewQCheckBox2("http bypass", ssrMicroClientGUI.settingWindow)
	//httpBypassCheckBox.SetChecked(ssrMicroClientGUI.settingConfig.HttpWithBypass)
	//httpBypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 40),
	//	core.NewQPoint2(450, 70)))

	//localAddressLabel := widgets.NewQLabel2("SSRAddress", ssrMicroClientGUI.settingWindow, 0)
	//localAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80),
	//	core.NewQPoint2(80, 110)))
	//localAddressLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	//localAddressLineText.SetText(ssrMicroClientGUI.settingConfig.LocalAddress)
	//localAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(90, 80),
	//	core.NewQPoint2(200, 110)))
	//
	//localPortLabel := widgets.NewQLabel2("SSRPort", ssrMicroClientGUI.settingWindow, 0)
	//localPortLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 80),
	//	core.NewQPoint2(300, 110)))
	//localPortLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	//localPortLineText.SetText(ssrMicroClientGUI.settingConfig.LocalPort)
	//localPortLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(310, 80),
	//	core.NewQPoint2(420, 110)))

	httpAddressLabel := widgets.NewQLabel2("http", ssrMicroClientGUI.settingWindow, 0)
	httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120),
		core.NewQPoint2(70, 150)))
	httpAddressLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	httpAddressLineText.SetText(ssrMicroClientGUI.settingConfig.HttpProxyAddressAndPort)
	httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120),
		core.NewQPoint2(210, 150)))

	socks5BypassAddressLabel := widgets.NewQLabel2("socks5",
		ssrMicroClientGUI.settingWindow, 0)
	socks5BypassAddressLabel.SetGeometry(core.
		NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
	socks5BypassLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	socks5BypassLineText.SetText(ssrMicroClientGUI.settingConfig.Socks5WithBypassAddressAndPort)
	socks5BypassLineText.SetGeometry(core.NewQRect2(core.
		NewQPoint2(300, 120), core.NewQPoint2(420, 150)))

	dnsServerLabel := widgets.NewQLabel2("DNS", ssrMicroClientGUI.settingWindow, 0)
	dnsServerLabel.SetGeometry(core.NewQRect2(core.
		NewQPoint2(10, 160), core.NewQPoint2(100, 190)))
	dnsServerLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	dnsServerLineText.SetText(ssrMicroClientGUI.settingConfig.DnsServer)
	dnsServerLineText.SetGeometry(core.NewQRect2(core.
		NewQPoint2(110, 160), core.NewQPoint2(420, 190)))

	ssrPathLabel := widgets.NewQLabel2("ssrPath", ssrMicroClientGUI.settingWindow, 0)
	ssrPathLabel.SetGeometry(core.NewQRect2(core.
		NewQPoint2(10, 200), core.NewQPoint2(100, 230)))
	ssrPathLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	ssrPathLineText.SetText(ssrMicroClientGUI.settingConfig.SsrPath)
	ssrPathLineText.SetGeometry(core.NewQRect2(core.
		NewQPoint2(110, 200), core.NewQPoint2(420, 230)))

	BypassFileLabel := widgets.NewQLabel2("bypassFilePath", ssrMicroClientGUI.settingWindow, 0)
	BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240),
		core.NewQPoint2(100, 270)))
	BypassFileLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	BypassFileLineText.SetText(ssrMicroClientGUI.settingConfig.BypassFile)
	BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 240),
		core.NewQPoint2(420, 270)))

	applyButton := widgets.NewQPushButton2("apply", ssrMicroClientGUI.settingWindow)
	applyButton.ConnectClicked(func(bool2 bool) {
		if socks5BypassLineText.Text() == "127.0.0.1:1083" || socks5BypassLineText.Text() == "0.0.0.0:1083" {
			ssrMicroClientGUI.MessageBox("You cant set the socks5 port to 1083,Please change it.")
			return
		}
		ssrMicroClientGUI.settingConfig.AutoStartSsr = autoStartSsr.IsChecked()
		ssrMicroClientGUI.settingConfig.HttpProxy = httpProxyCheckBox.IsChecked()
		ssrMicroClientGUI.settingConfig.Bypass = bypassCheckBox.IsChecked()
		ssrMicroClientGUI.settingConfig.IsDNSOverHTTPS = DnsOverHttpsCheckBox.IsChecked()
		//ssrMicroClientGUI.settingConfig.HttpWithBypass = httpBypassCheckBox.IsChecked()
		//ssrMicroClientGUI.settingConfig.LocalAddress = localAddressLineText.Text()
		//ssrMicroClientGUI.settingConfig.LocalPort = localPortLineText.Text()
		//ssrMicroClientGUI.settingConfig.PythonPath = pythonPathLineText.Text()
		ssrMicroClientGUI.settingConfig.SsrPath = ssrPathLineText.Text()
		ssrMicroClientGUI.settingConfig.BypassFile = BypassFileLineText.Text()
		ssrMicroClientGUI.settingConfig.HttpProxyAddressAndPort = httpAddressLineText.Text()
		ssrMicroClientGUI.settingConfig.Socks5WithBypassAddressAndPort = socks5BypassLineText.Text()
		ssrMicroClientGUI.settingConfig.DnsServer = dnsServerLineText.Text()

		if err := config2.SettingEnCodeJSON(ssrMicroClientGUI.configPath, ssrMicroClientGUI.settingConfig); err != nil {
			//log.Println(err)
			ssrMicroClientGUI.MessageBox(err.Error())
		}
		ssrMicroClientGUI.server.ServerRestart()
	})
	applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280),
		core.NewQPoint2(90, 310)))

	ssrMicroClientGUI.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		ssrMicroClientGUI.settingWindow.Close()
	})
}
