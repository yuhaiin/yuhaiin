package gui

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

type subscribe struct {
	window       *widgets.QMainWindow
	subLabel     *widgets.QLabel
	subCombobox  *widgets.QComboBox
	deleteButton *widgets.QPushButton
	lineText     *widgets.QLineEdit
	addButton    *widgets.QPushButton
}

func NewSubscribe() *subscribe {
	s := &subscribe{}
	s.window = widgets.NewQMainWindow(nil, core.Qt__Window)
	s.window.SetWindowTitle("subscribe")
	s.window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		s.window.Hide()
	})
	s.window.ConnectShowEvent(func(event *gui.QShowEvent) {
		s.subCombobox.Clear()
		links, err := apiC.GetSubLinks(context.Background(), &empty.Empty{})
		if err != nil {
			MessageBox(err.Error())
			return
		}
		s.subCombobox.AddItems(links.Value)
	})

	s.create()
	s.setLayout()
	s.setListener()

	return s
}

func (s *subscribe) create() {
	s.subLabel = widgets.NewQLabel2("SUBSCRIPTION", nil, core.Qt__Widget)
	s.subCombobox = widgets.NewQComboBox(nil)
	s.deleteButton = widgets.NewQPushButton2("DELETE", nil)
	s.lineText = widgets.NewQLineEdit(nil)
	s.addButton = widgets.NewQPushButton2("ADD", nil)
}

func (s *subscribe) setLayout() {
	windowLayout := widgets.NewQGridLayout2()
	windowLayout.AddWidget2(s.subLabel, 0, 0, 0)
	windowLayout.AddWidget2(s.subCombobox, 0, 1, 0)
	windowLayout.AddWidget2(s.deleteButton, 0, 2, 0)
	windowLayout.AddWidget3(s.lineText, 1, 0, 1, 2, 0)
	windowLayout.AddWidget2(s.addButton, 1, 2, 0)

	centralWidget := widgets.NewQWidget(s.window, core.Qt__Widget)
	centralWidget.SetLayout(windowLayout)
	s.window.SetCentralWidget(centralWidget)
}

func (s *subscribe) setListener() {
	s.deleteButton.ConnectClicked(s.deleteCall)
	s.addButton.ConnectClicked(s.addCall)
}

func (s *subscribe) addCall(_ bool) {
	links, err := apiC.GetSubLinks(context.Background(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	linkToAdd := s.lineText.Text()
	if linkToAdd == "" {
		return
	}
	for index := range links.Value {
		if links.Value[index] == linkToAdd {
			return
		}
	}

	links, err = apiC.AddSubLink(context.Background(), &wrappers.StringValue{Value: linkToAdd})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	s.subCombobox.Clear()
	s.subCombobox.AddItems(links.Value)
	s.lineText.Clear()
}

func (s *subscribe) deleteCall(_ bool) {
	links, err := apiC.DeleteSubLink(context.Background(), &wrappers.StringValue{Value: s.subCombobox.CurrentText()})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	s.subCombobox.Clear()
	s.subCombobox.AddItems(links.Value)
}
