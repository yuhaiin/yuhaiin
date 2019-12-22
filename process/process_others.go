// +build !windows

package process

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"SsrMicroClient/config/config"
	"SsrMicroClient/config/configjson"
	"SsrMicroClient/microlog"
)

// Start start ssr
func Start(configPath string) {
	// pid, status := Get(configPath)
	// if status == true {
	// 	log.Println("already have run at " + pid)
	// 	return
	// }
	argument := config.GetConfigArgument()
	nodeAndConfig, _ := configjson.GetNowNode(configPath)
	for key, value := range config.GetConfig(configPath) {
		nodeAndConfig[key] = value
	}
	// now not use
	// logFile , PidFile
	nodeAndConfigArgument := []string{"server", "serverPort", "protocol", "method",
		"obfs", "password", "obfsparam", "protoparam", "localAddress",
		"localPort", "timeout"}
	// argumentArgument := []string{"localAddress", "localPort", "logFile", "pidFile", "workers", "acl", "timeout"}
	argumentSingle := []string{"fastOpen", "udpTrans"}

	var cmdArray []string
	if nodeAndConfig["ssrPath"] != "" {
		cmdArray = append(cmdArray, nodeAndConfig["ssrPath"])
	}
	for _, nodeA := range nodeAndConfigArgument {
		if nodeAndConfig[nodeA] != "" {
			cmdArray = append(cmdArray, argument[nodeA], nodeAndConfig[nodeA])
		}
	}
	/*
		for _, argumentA := range argumentArgument {
			if config[argumentA] != "" {
				cmdArray = append(cmdArray, argument[argumentA], config[argumentA])
			}
		}*/

	for _, argumentS := range argumentSingle {
		if nodeAndConfig[argumentS] != "" {
			cmdArray = append(cmdArray, argument[argumentS])
		}
	}
	cmd := exec.Command(nodeAndConfig["pythonPath"], cmdArray...)
	microlog.Debug(nodeAndConfig["pythonPath"], cmdArray)

	_ = cmd.Run()
	_ = ioutil.WriteFile(nodeAndConfig["pidFile"], []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
}

// Stop stop ssr process
func Stop(configPath string) {
	pid, exist := Get(configPath)
	if exist == true {
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
func Get(configPath string) (pid string, isExist bool) {
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

// GetProcessStatus Get run status
func GetProcessStatus(path string) (pid string, isExist bool) {
	// configTemp := strings.Split(config.Read_config_file(path)["Pid_file"], " ")[1]
	pidTemp, err := ioutil.ReadFile(path)
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
func StartByArgument(configPath, functionName string) {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return
	}
	// log.Println(executablePath)
	switch functionName {
	case "ssr":
		pid, status := Get(configPath)
		if status == true {
			log.Println("already have run at " + pid)
			return
		}
		first, err := os.StartProcess(executablePath, []string{executablePath, "-sd", "ssr"}, &os.ProcAttr{
			Sys: &syscall.SysProcAttr{
				Setsid: true,
			},
		})
		if err != nil {
			log.Println(err)
			return
		}
		log.Println(first.Pid)
		_, _ = first.Wait()

		pid, status = Get(configPath)
		if status == true {
			log.Println("start ssr at deamon(pid=" + pid + ") successful!")
		} else {
			log.Println("run ssr failed!")
		}
		//case "http":
		//	argument := config.GetConfig(configPath)
		//	fmt.Println("http proxy address:" + argument["httpProxy"])
		//	first, err := os.StartProcess(executablePath, []string{executablePath, "-sd", "httpB"}, &os.ProcAttr{
		//		Sys: &syscall.SysProcAttr{
		//			Setsid: true,
		//		},
		//	})
		//	if err != nil {
		//		log.Println(err)
		//		return
		//	}
		//	log.Println(first.Pid)
		//	_, _ = first.Wait()
		//
		//case "httpBp":
		//	argument := config.GetConfig(configPath)
		//	fmt.Println("http proxy address:" + argument["httpProxy"])
		//	first, err := os.StartProcess(executablePath, []string{executablePath, "-sd", "httpBBp"}, &os.ProcAttr{
		//		Sys: &syscall.SysProcAttr{
		//			Setsid: true,
		//		},
		//	})
		//	if err != nil {
		//		log.Println(err)
		//		return
		//	}
		//	log.Println(first.Pid)
		//	_, _ = first.Wait()
	}
}
