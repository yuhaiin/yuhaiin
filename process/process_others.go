// +build !windows

package ssr_process

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"../config"
)

// Stop stop ssr process
func Stop(path string) {
	pid, exist := Get(path)
	if exist == true {

		// cmd_temp = "kill " + pid
		// cmd = exec.Command("sh", "-c", cmd_temp)
		pidI, err := strconv.Atoi(pid)
		if err != nil {
			log.Println(err)
			return
		}
		// syscall.Kill(pidI, syscall.SIGQUIT)
		err = syscall.Kill(pidI, syscall.SIGKILL)
		if err != nil {
			log.Println(err)
			return
		}
		// syscall.Kill(pidI, syscall.SIGCHLD)

		fmt.Println("Process pid=" + pid + " killed!")
	} else {
		log.Printf("\n")
		log.Printf("cant find the process: %s", pid)
		log.Printf("please start ssr first.\n")
		return
	}
}

// Get Get run status
func Get(configPath string) (pid string, isexist bool) {
	// configTemp := strings.Split(config.Read_config_file(path)["Pid_file"], " ")[1]
	pidTemp, err := ioutil.ReadFile(config.GetConfig(configPath)["pidFile"])
	if err != nil {
		log.Println(err)
		log.Println("cant find the file,please run ssr start.")
		return
	}
	pid = strings.Replace(string(pidTemp), "\r\n", "", -1)
	pidI, _ := strconv.Atoi(pid)

	// 检测类unix进程
	if err := syscall.Kill(pidI, 0); err != nil {
		return "", false
	}
	return pid, true
}

// StartByArgument to run ssr  deamon at golang use argument
func StartByArgument(configPath, sqlPath string) {
	pid, status := Get(configPath)
	if status == true {
		log.Println("already have run at " + pid)
		return
	}

	dir2, _ := filepath.Abs(os.Args[0])
	log.Println(dir2)
	first, err := os.StartProcess(dir2, []string{dir2, "-d"}, &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(first.Pid)
	first.Wait()

	pid, status = Get(configPath)
	if status == true {
		log.Println("start ssr at deamon(pid=" + pid + ") successful!")
	} else {
		log.Println("run ssr failed!")
	}
}
