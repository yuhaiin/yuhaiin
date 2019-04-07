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

	"../config"
	// _ "github.com/mattn/go-sqlite3"
)

func Start(config_path, db_path string) {
	ssr_config := config.Read_config(config_path, db_path)

	cmd_temp := ssr_config.Argument["Python_path"] + ssr_config.Argument["Ssr_path"] + ssr_config.
		Argument["Local_address"] + ssr_config.Argument["Local_port"] + ssr_config.
		Argument["Log_file"] + ssr_config.Argument["Pid_file"] + ssr_config.Argument["Fast_open"] + ssr_config.
		Argument["Workers"] + ssr_config.Argument["Connect_verbose_info"] + ssr_config.
		Node["Server"] + ssr_config.Node["Server_port"] + ssr_config.Node["Protocol"] + ssr_config.
		Node["Method"] + ssr_config.Node["Obfs"] + ssr_config.Node["Password"] + ssr_config.
		Node["Obfsparam"] + ssr_config.Node["Protoparam"] + ssr_config.
		Argument["Acl"] + ssr_config.Argument["Deamon"]

	fmt.Println(cmd_temp)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", cmd_temp)
	} else {
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
		cmd = exec.Command("sh", "-c", cmd_temp)
	}
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
	//fmt.Println(ssr_config.python_path,ssr_config.config_path,ssr_config.log_file,ssr_config.pid_file,ssr_config.fast_open,ssr_config.workers,ssr_config.connect_verbose_info,ssr_config.ssr_path,ssr_config.server,ssr_config.server_port,ssr_config.protocol,ssr_config.method,ssr_config.obfs,ssr_config.password,ssr_config.obfsparam,ssr_config.protoparam)
}

func Stop(path string) {
	pid, exist := Get(path)
	if exist == true {
		var cmd_temp string
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd_temp = "taskkill /PID " + pid
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
		log.Println("\n")
		log.Printf("cant find the process: %s", pid)
		log.Println("please start ssr first.\n")
		return
	}
}

func Get(path string) (pid string, isexist bool) {
	config_temp := config.Read_config_file(path)
	pid_temp, err := ioutil.ReadFile(strings.Split(config_temp["Pid_file"], " ")[1])
	if err != nil {
		log.Println(err)
		log.Println("cant fild the file,please run ssr start.")
		return
	}
	pid = string(pid_temp)
	var cmd *exec.Cmd
	var out bytes.Buffer

	//检测windows进程
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "tasklist | findstr "+pid)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			fmt.Println("task not found", err, out.String())
		}
		re, _ := regexp.Compile(" {2,}")
		pid_not_eq := strings.Split(re.ReplaceAllString(out.String(), " "), " ")[1]
		if pid_not_eq == pid {
			return pid, true
		} else {
			return "", false
		}

		//检测类unix进程
	} else {
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
