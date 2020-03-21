package gui

import (
	"github.com/Asutorufa/SsrMicroClient/subscription"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

func (ssrMicroClientGUI *SsrMicroClientGUI) createSubscriptionWindow() {
	ssrMicroClientGUI.subscriptionWindow = widgets.NewQMainWindow(ssrMicroClientGUI.MainWindow, 0)
	ssrMicroClientGUI.subscriptionWindow.SetFixedSize2(700, 100)
	ssrMicroClientGUI.subscriptionWindow.SetWindowTitle("subscription")
	ssrMicroClientGUI.subscriptionWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		ssrMicroClientGUI.subscriptionWindow.Hide()
	})

	subLabel := widgets.NewQLabel2("subscription", ssrMicroClientGUI.subscriptionWindow,
		core.Qt__WindowType(0x00000000))
	subLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 10),
		core.NewQPoint2(130, 40)))
	subCombobox := widgets.NewQComboBox(ssrMicroClientGUI.subscriptionWindow)
	var link []string
	subRefresh := func() {
		subCombobox.Clear()
		var err error
		link, err = subscription.GetLink(ssrMicroClientGUI.configPath)
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}
		subCombobox.AddItems(link)
	}
	subRefresh()
	subCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 10),
		core.NewQPoint2(600, 40)))

	deleteButton := widgets.NewQPushButton2("delete", ssrMicroClientGUI.subscriptionWindow)
	deleteButton.ConnectClicked(func(bool2 bool) {
		linkToDelete := subCombobox.CurrentText()
		if err := subscription.RemoveLinkJSON(linkToDelete,
			ssrMicroClientGUI.configPath); err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}
		subRefresh()
	})
	deleteButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 10),
		core.NewQPoint2(690, 40)))

	lineText := widgets.NewQLineEdit(ssrMicroClientGUI.subscriptionWindow)
	lineText.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 50),
		core.NewQPoint2(600, 80)))

	addButton := widgets.NewQPushButton2("add", ssrMicroClientGUI.subscriptionWindow)
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
		if err := subscription.AddLinkJSON(linkToAdd, ssrMicroClientGUI.configPath); err != nil {
			//log.Println(err)
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}
		subRefresh()
	})
	addButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 50),
		core.NewQPoint2(690, 80)))

	ssrMicroClientGUI.subscriptionWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		ssrMicroClientGUI.subscriptionWindow.Close()
	})
}
