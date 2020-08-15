package gui

import (
	"context"
	"fmt"
	"sort"

	"github.com/Asutorufa/yuhaiin/api"

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
	nameLabel    *widgets.QLabel
	nameLineText *widgets.QLineEdit
	typeLabel    *widgets.QLabel
	typeCombobox *widgets.QComboBox
	urlLabel     *widgets.QLabel
	urlLineText  *widgets.QLineEdit
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

	s.create()
	s.setLayout()
	s.setListener()

	return s
}

func (s *subscribe) create() {
	s.subLabel = widgets.NewQLabel2("SUBSCRIPTION", nil, core.Qt__Widget)
	s.subCombobox = widgets.NewQComboBox(nil)
	s.deleteButton = widgets.NewQPushButton2("DELETE", nil)
	s.nameLabel = widgets.NewQLabel2("Name", nil, core.Qt__Widget)
	s.nameLineText = widgets.NewQLineEdit(nil)
	s.typeLabel = widgets.NewQLabel2("Type", nil, core.Qt__Widget)
	s.typeCombobox = widgets.NewQComboBox(nil)
	s.urlLabel = widgets.NewQLabel2("Link", nil, core.Qt__Widget)
	s.urlLineText = widgets.NewQLineEdit(nil)
	s.addButton = widgets.NewQPushButton2("SAVE", nil)
}

func (s *subscribe) setLayout() {
	windowLayout := widgets.NewQGridLayout2()
	windowLayout.AddWidget2(s.subLabel, 0, 0, 0)
	windowLayout.AddWidget2(s.subCombobox, 0, 1, 0)
	windowLayout.AddWidget2(s.deleteButton, 0, 2, 0)
	windowLayout.AddWidget2(s.nameLabel, 1, 0, 0)
	windowLayout.AddWidget2(s.nameLineText, 1, 1, 0)
	windowLayout.AddWidget2(s.urlLabel, 2, 0, 0)
	windowLayout.AddWidget2(s.urlLineText, 2, 1, 0)
	windowLayout.AddWidget2(s.typeLabel, 3, 0, 0)
	windowLayout.AddWidget2(s.typeCombobox, 3, 1, 0)
	windowLayout.AddWidget2(s.addButton, 3, 2, 0)

	centralWidget := widgets.NewQWidget(s.window, core.Qt__Widget)
	centralWidget.SetLayout(windowLayout)
	s.window.SetCentralWidget(centralWidget)
}

func (s *subscribe) setListener() {
	s.window.ConnectShowEvent(s.showCall)
	s.deleteButton.ConnectClicked(s.deleteCall)
	s.subCombobox.ConnectCurrentTextChanged(s.comboboxChangeCall)
	s.addButton.ConnectClicked(s.addCall)
}

func (s *subscribe) showCall(_ *gui.QShowEvent) {
	links, err := grpcSub.GetSubLinks(context.Background(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	s.sortAndShow(links.Value)
}

func (s *subscribe) sortAndShow(links map[string]*api.Link) {
	var keys []string
	for key := range links {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	s.subCombobox.Clear()
	for index := range keys {
		s.subCombobox.AddItem(keys[index], core.NewQVariant23(
			map[string]*core.QVariant{
				"type": core.NewQVariant12(links[keys[index]].Type),
				"url":  core.NewQVariant15(links[keys[index]].Url),
			},
		),
		)
	}
}

func (s *subscribe) comboboxChangeCall(name string) {
	s.nameLineText.SetText(name)
	s.urlLineText.SetText(s.subCombobox.CurrentData(int(core.Qt__UserRole)).ToMap()["url"].ToString())
	s.typeCombobox.SetCurrentText(s.subCombobox.CurrentData(int(core.Qt__UserRole)).ToMap()["type"].ToString())
}

func (s *subscribe) addCall(_ bool) {
	name := s.nameLineText.Text()
	url := s.urlLineText.Text()
	links, err := grpcSub.AddSubLink(context.Background(), &api.Link{Name: name, Type: s.typeCombobox.CurrentText(), Url: url})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	s.sortAndShow(links.Value)
	MessageBox(fmt.Sprintf("Add %s: %s Successful", name, url))
}

func (s *subscribe) deleteCall(_ bool) {
	links, err := grpcSub.DeleteSubLink(context.Background(), &wrappers.StringValue{Value: s.subCombobox.CurrentText()})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	s.sortAndShow(links.Value)
	MessageBox("Delete Successful")
}
