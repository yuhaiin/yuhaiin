 package socks5

 import (
	 "net"
	 "fmt"
	 "time"
 )


func Delay_test(local_server,local_port string){
	conn,err := net.Dial("tcp",local_server+":"+local_port)
	if err != nil{
		fmt.Println(err)
		return
	}


	//发送socks5验证信息
	//socks版本 连接方式 验证方式
	_,err = conn.Write([]byte{5,1,0})
	var b [2]byte
	status,err := conn.Read(b[:])
	if err!=nil{
		fmt.Println(err)
		return
	}
	fmt.Println(b)
	fmt.Println(status)


	/*
	socks5 protocol
	socks_version link_style none ipv4/ipv6/domain address port
	socks5协议
	socks版本 连接方式 保留字节 域名/ipv4/ipv6 域名 端口
	*/
	domain := "www.google.com"
	before := []byte{5,1,0,3,byte(len(domain))}
	de := []byte(domain)
	port := []byte{0x1,0xbb}
	head_temp := append(before,de...)
	head := append(head_temp,port...)

	fmt.Println(head)

	_,err = conn.Write(head)
	if err!=nil{
		fmt.Println(err)
		return
	}

	var c [10]byte
	status_2,err := conn.Read(c[:])
	if err!=nil{
		fmt.Println(err)
		return
	}
	fmt.Println(status_2)
	fmt.Println(c)


	//进行数据请求

	_,err = conn.Write([]byte("GET /generate_204/ HTTP/2.0\r\n"))
	//_,err = conn.Write([]byte("GET / HTTP/2.0\r\nHost: www.google.com\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\nAccept-Language: cn\r\n"))
	if err!=nil{
		fmt.Println(err)
		return
	}
	var d [1024]byte

	temp := time.Now()

	status_3,err := conn.Read(d[:])

	deply := time.Since(temp)
	fmt.Println(deply)

	fmt.Println(status_3)
	fmt.Println(string(d[:]))

	conn.Close()
}