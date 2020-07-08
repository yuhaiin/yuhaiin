// +build windows

package gui

func (s *setting) extends() {
	s.redirProxyAddressLineText.SetDisabled(true)
}
