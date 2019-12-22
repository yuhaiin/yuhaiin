package process

import (
	ssrinit "SsrMicroClient/init"
	"testing"
	"time"
)

func TestStart(t *testing.T) {
	cmd := GetSsrCmd(ssrinit.GetConfigAndSQLPath())
	go func() {
		t.Log(cmd.Args)
		if err := cmd.Run(); err != nil {
			t.Log(err)
		}
		t.Log("stop")
	}()
	time.Sleep(1 * time.Second)

	//cmd := exec.Command("sh","-c"," python /home/asutorufa/.config/SSRSub/shadowsocksr/shadowsocks/local.py -s l2127-z5nwo5ve.node.endpoint.top -p 537 -O auth_aes128_md5 -m chacha20-ietf -o http_post -k BH63UA -g 823224308.apple.com -G 4308:0qF3fS -b 127.0.0.1 -l 1083 --fast-open -v")
	//	stdout, err := cmd.StdoutPipe()
	//	if err != nil {
	//		fmt.Println(err)
	//		return
	//	}
	//	stderr,err := cmd.StderrPipe()
	//	if err != nil {
	//		fmt.Println(err)
	//		return
	//	}
	//	_ = cmd.Start()
	//	stdoutReader := bufio.NewReader(stdout)
	//	stderrReader := bufio.NewReader(stderr)
	//	//实时循环读取输出流中的一行内容
	//	go func() {
	//
	//	for {
	//		line,_, err2 := stdoutReader.ReadLine()
	//		if err2 != nil || io.EOF == err2 {
	//			break
	//		}
	//		fmt.Println(string(line))
	//	}
	//	}()
	//	go func() {
	//		for {
	//			line,_, err2 := stderrReader.ReadLine()
	//			if err2 != nil || io.EOF == err2 {
	//				break
	//			}
	//			fmt.Println(string(line))
	//		}
	//	}()
	//	_ = cmd.Wait()
}
