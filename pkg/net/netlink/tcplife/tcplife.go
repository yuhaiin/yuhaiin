package tcplife

import (
	"fmt"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go tool bpf2go -tags linux tcplife tcplife.bpf.c

type Event struct {
	Pid     uint32
	Uid     uint32
	Sport   uint16
	Dport   uint16
	Family  uint8
	Action  uint8
	State   uint8 // TCP state
	Network uint8 // 0 = tcp, 1 = udp
	_Pad    [2]byte

	Saddr [16]byte
	Daddr [16]byte
	Comm  [16]byte
}

func TestTcplife(f func(Event)) error {
	var obj tcplifeObjects
	err := loadTcplifeObjects(&obj, nil)
	if err != nil {
		return err
	}
	defer obj.Close()

	kp1, err := link.AttachTracing(link.TracingOptions{
		Program: obj.TcpConnect,
	})
	if err != nil {
		log.Warn("attach tcpConnect failed", "err", err)
	} else {
		defer kp1.Close()
	}

	// kp4, err := link.Tracepoint("sock", "inet_sock_set_state", obj.TpInetSockSetState, nil)
	// if err != nil {
	// 	log.Warn("tracepoint sock/inet_sock_set_state failed", "err", err)
	// } else {
	// 	defer kp4.Close()
	// }

	kp2, err := link.AttachTracing(link.TracingOptions{
		Program: obj.TcpClose,
	})
	if err != nil {
		log.Warn("attach tcpClose failed", "err", err)
	} else {
		defer kp2.Close()
	}

	kp3, err := link.AttachTracing(link.TracingOptions{
		Program: obj.InetBindExit,
	})
	if err != nil {
		log.Warn("attach inetBindExit failed", "err", err)
	} else {
		defer kp3.Close()
	}

	r, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return err
	}

	fmt.Println("start read")

	for {
		record, err := r.Read()
		if err != nil {
			return err
		}

		var e Event
		copy((*[unsafe.Sizeof(e)]byte)(unsafe.Pointer(&e))[:], record.RawSample)

		f(e)
	}
}
