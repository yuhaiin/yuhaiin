package ssr_process

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"../config"
	getdelay "../net"
	// _ "github.com/mattn/go-sqlite3"
)

type ssr_start struct {
	cmd_temp string
}

func (*ssr_start) get_string(configPath, dbPath string) (string, config.Ssr_config) {
	ssrConfig := config.Read_config(configPath, dbPath)

	// Generate shadowsocksr start cmd
	var argument string
	nodeArgument := []string{"Server", "Server_port", "Protocol", "Method", "Obfs", "Password", "Obfsparam", "Protoparam"}
	argumentArgument := []string{"Python_path", "Ssr_path", "Local_address", "Local_port", "Log_file", "Pid_file", "Fast_open", "Workers", "Connect_verbose_info", "Acl", "Timeout", "Deamon"}
	for _, ssrArgument := range argumentArgument {
		argument += ssrConfig.Argument[ssrArgument]
		if ssrArgument == "Connect_verbose_info" {
			for _, nodeArgument := range nodeArgument {
				argument += ssrConfig.Node[nodeArgument]
			}
		}
	}

	return argument, ssrConfig
	/*
		return ssr_config.Argument["Python_path"] + ssr_config.Argument["Ssr_path"] + ssr_config.
				Argument["Local_address"] + ssr_config.Argument["Local_port"] + ssr_config.
				Argument["Log_file"] + ssr_config.Argument["Pid_file"] + ssr_config.Argument["Fast_open"] + ssr_config.
				Argument["Workers"] + ssr_config.Argument["Connect_verbose_info"] + ssr_config.
				Node["Server"] + ssr_config.Node["Server_port"] + ssr_config.Node["Protocol"] + ssr_config.
				Node["Method"] + ssr_config.Node["Obfs"] + ssr_config.Node["Password"] + ssr_config.
				Node["Obfsparam"] + ssr_config.Node["Protoparam"] + ssr_config.
				Argument["Acl"] + ssr_config.Argument["Timeout"] + ssr_config.Argument["Deamon"], ssr_config.
				Argument["Local_port"], ssr_config.Argument["Pid_file"], []string{ssr_config.Node["Server"], ssr_config.Node["Server_port"]}
	*/
}

func (*ssr_start) windows(path, cmd_temp, Local_port, pid_path string) {
	vbs_deamon := "CreateObject(\"Wscript.Shell\").run \"cmd /c " + cmd_temp + "\",0"
	vbs_path := path + "\\SSRSub_deamon.vbs"
	ioutil.WriteFile(vbs_path, []byte(vbs_deamon), 0644)
	cmd := exec.Command("cmd", "/c", vbs_path)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf(fmt.Sprint(err) + ": " + stderr.String())
		return
	}
	fmt.Printf("Result: %s\n", out.String())

	time.Sleep(time.Duration(500) * time.Millisecond)
	cmd = exec.Command("cmd", "/c", "netstat -ano | findstr "+strings.Split(Local_port, " ")[1])
	cmd.Stdout = &out
	cmd.Run()
	re, _ := regexp.Compile(" {2,}")
	pid_ := strings.Split(re.ReplaceAllString(out.String(), " "), " ")
	pid := pid_[len(pid_)-1]
	ioutil.WriteFile(strings.Split(pid_path, " ")[1], []byte(pid), 0644)
}

func (*ssr_start) other_os(cmd_temp string) {
	/*
				get_sh_cmd := exec.Command("which", "sh")
				var out bytes.Buffer
				get_sh_cmd.Stdout = &out
				err := get_sh_cmd.Run()
				if err != nil {
					log.Fatal(err)
					log.Fatal("get sh error.")
					return
		        }
		        cmd = exec.Command(out.String(), "-c", cmd_temp)
	*/
	cmd := exec.Command("sh", "-c", cmd_temp)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf(fmt.Sprint(err) + ": " + stderr.String())
		return
	}
	fmt.Printf("Result: %s\n", out.String())
}

func Start(config_path, db_path string) {
	var ssr_start ssr_start
	// cmd_temp, Local_port, pid_path, server := ssr_start.get_string(config_path, db_path)
	cmd_temp, ssrConfig := ssr_start.get_string(config_path, db_path)
	fmt.Println(cmd_temp)
	if runtime.GOOS == "windows" {
		ssr_start.windows(config_path, cmd_temp, ssrConfig.Argument["Local_port"], ssrConfig.Argument["Pid_file"])
	} else {
		ssr_start.other_os(cmd_temp)
	}
	// fmt.Println(server)
	delay, err := getdelay.Tcp_delay(strings.Split(ssrConfig.Node["Server"], " ")[1], strings.Split(ssrConfig.Node["Server_port"], " ")[1])
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("当前节点延迟:", delay)
	// fmt.Println(ssr_config.python_path,ssr_config.config_path,ssr_config.log_file,ssr_config.pid_file,ssr_config.fast_open,ssr_config.workers,ssr_config.connect_verbose_info,ssr_config.ssr_path,ssr_config.server,ssr_config.server_port,ssr_config.protocol,ssr_config.method,ssr_config.obfs,ssr_config.password,ssr_config.obfsparam,ssr_config.protoparam)
}

func Stop(path string) {
	pid, exist := Get(path)
	if exist == true {
		var cmd_temp string
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd_temp = "taskkill /PID " + pid + " /F"
			fmt.Println(cmd_temp)
			cmd = exec.Command("cmd", "/c", cmd_temp)
		} else {
			cmd_temp = "kill " + pid
			cmd = exec.Command("sh", "-c", cmd_temp)
		}
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			log.Printf(fmt.Sprint(err) + ": " + stderr.String())
			return
		}
		fmt.Printf("Result: %s\n", out.String())
	} else {
		log.Printf("\n")
		log.Printf("cant find the process: %s", pid)
		log.Printf("please start ssr first.\n")
		return
	}
}

func Get(path string) (pid string, isexist bool) {
	config_temp := config.Read_config_file(path)
	pid_temp, err := ioutil.ReadFile(strings.Split(config_temp["Pid_file"], " ")[1])
	if err != nil {
		log.Println(err)
		log.Println("cant find the file,please run ssr start.")
		return
	}
	pid = strings.Replace(string(pid_temp), "\r\n", "", -1)
	var cmd *exec.Cmd
	var out bytes.Buffer

	//检测windows进程
	switch {
	case runtime.GOOS == "windows":
		cmd := exec.Command("cmd", "/c", "netstat -ano | findstr "+strings.Split(config.Read_config_file(path)["Local_port"], " ")[1])
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			fmt.Println("task not found", err, out.String())
		}
		re, _ := regexp.Compile(" {2,}")
		pid_not_eq_ := strings.Split(re.ReplaceAllString(out.String(), " "), " ")
		pid_not_eq := strings.Replace(pid_not_eq_[len(pid_not_eq_)-1], "\r\n", "", -1)
		switch {
		case pid_not_eq == pid:
			return pid, true
		default:
			return "", false
		}

		//检测类unix进程
	default:
		cmd = exec.Command("sh", "-c", "ls /proc | grep  -w ^"+pid)
	}
	cmd.Stdout = &out
	err = cmd.Run()
	if out.String() != "" {
		return pid, true
	} else {
		return "", false
	}
}
