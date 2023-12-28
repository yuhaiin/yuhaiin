package server

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"

func (s *Socks5) startUDPServer() error {
	packet, err := s.lis.Packet(s.ctx)
	if err != nil {
		return err
	}

	go func() {
		defer packet.Close()
		yuubinsya.StartUDPServer(s.ctx, packet, s.udpChannel, nil, true)
	}()

	return nil
}
