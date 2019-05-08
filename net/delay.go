package getdelay

import (
	"fmt"
	"log"
	"net"
	"time"
)

type delay struct{}

func (*delay) creat_dial(local_server, local_port string) net.Conn {
	conn, err := net.Dial("tcp", local_server+":"+local_port)
	if err != nil {
		log.Println("请先连接ssr再进行测试")
		log.Println(err)
		return conn
	}
	return conn
}

func (*delay) socks5_first_verify(conn net.Conn) error {
	//发送socks5验证信息
	//socks版本 连接方式 验证方式
	_, err := conn.Write([]byte{5, 1, 0})
	var b [2]byte
	_, err = conn.Read(b[:])
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println(b)
	return nil
}

func (*delay) socks5_second_verify(conn net.Conn) error {
	// socks5 protocol
	// socks_version link_style none ipv4/ipv6/domain address port
	// socks5协议
	// socks版本 连接方式 保留字节 域名/ipv4/ipv6 域名 端口

	domain := "www.google.com"
	before := []byte{5, 1, 0, 3, byte(len(domain))}
	de := []byte(domain)
	port := []byte{0x1, 0xbb}
	head_temp := append(before, de...)
	head := append(head_temp, port...)

	_, err := conn.Write(head)
	if err != nil {
		fmt.Println(err)
		return err
	}

	var c [10]byte
	_, err = conn.Read(c[:])
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println(c)
	return nil
}

func (*delay) socks5_send_and_read(conn net.Conn) error {
	//进行数据请求
	re := "Get / HTTP/2.0\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: ja,zh-CN;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nDNT: 1\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nTE: Trailers\r\n"
	_, err := conn.Write([]byte(re))
	if err != nil {
		fmt.Println(err)
		return err
	}
	var d [1024]byte

	temp := time.Now()
	_, err = conn.Read(d[:])
	if err != nil {
		fmt.Println(err)
		return err
	}
	delay := time.Since(temp)
	fmt.Println(delay)
	fmt.Println(string(d[:]))
	return nil
}

func Get_delay(local_server, local_port string) {
	var delay delay
	conn := delay.creat_dial(local_server, local_port)
	err := delay.socks5_first_verify(conn)
	if err != nil {
		log.Println("socks5 first verify error")
		log.Println(err)
		conn.Close()
		return
	}
	err = delay.socks5_second_verify(conn)
	if err != nil {
		log.Println("socks5 second verify error")
		log.Println(err)
		conn.Close()
		return
	}
	err = delay.socks5_send_and_read(conn)
	if err != nil {
		log.Println("get delay last error")
		log.Println(err)
		conn.Close()
		return
	}
	conn.Close()
}
