// +build windows

package process

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"../config/config"
)

// Stop stop ssr process
func Stop(configPath string) {
	pid, exist := Get(configPath)
	// pidI, err := strconv.Atoi(pid)
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	if exist == true {
		// cmdTemp := "taskkill /PID " + pid + " /F"
		// fmt.Println(cmdTemp)
		// cmd := exec.Command("cmd", "/c", cmdTemp)

		err := exec.Command("taskkill", "/PID", pid, "/F").Run()
		if err != nil {
			log.Println(err)
			return
		}

		// process, err := os.FindProcess(pidI)
		// if err != nil {
		// 	log.Println(err)
		// 	return
		// }
		// // process.Release()
		// // process.Kill()
		// process.Signal()
		// process.Wait()

		// var out bytes.Buffer
		// var stderr bytes.Buffer
		// cmd.Stdout = &out
		// cmd.Stderr = &stderr
		// cmd.Run()
		// if err != nil {
		// 	log.Printf(fmt.Sprint(err) + ": " + stderr.String())
		// 	return
		// }
		// fmt.Printf("Result: %s\n", out.String())

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
	pidTemp, err := ioutil.ReadFile(config.GetConfig(configPath)["pidFile"])
	if err != nil {
		log.Println(err)
		log.Println("cant find the file,please run ssr start.")
		return
	}
	pid = strings.Replace(string(pidTemp), "\r\n", "", -1)

	// check windows ssr background status
	cmd := exec.Command("cmd", "/c", `wmic process get processid | findstr `+pid)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	log.Println(out.Len())
	if out.Len() == 0 {
		return "", false
	}
	return pid, true
	// FindProcess have bug that all success same with linux
	// if _, err := os.FindProcess(pidI); err != nil {
	// 	return "", false
	// }
	// return pid, true
}

// Get Get run status
func GetProcessStatus(path string) (pid string, isExist bool) {
	pidTemp, err := ioutil.ReadFile(path)
	if err != nil {
		log.Println(err)
		log.Println("cant find the file,please run ssr start.")
		return
	}
	pid = strings.Replace(string(pidTemp), "\r\n", "", -1)

	// check windows ssr background status
	cmd := exec.Command("cmd", "/c", `wmic process get processid | findstr `+pid)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	log.Println(out.Len())
	if out.Len() == 0 {
		return "", false
	}
	return pid, true
	// FindProcess have bug that all success same with linux
	// if _, err := os.FindProcess(pidI); err != nil {
	// 	return "", false
	// }
	// return pid, true
}

// StartByArgument to run ssr  deamon at golang use argument
func StartByArgument(configPath, functionName string) {

	// dir2, _ := filepath.Abs(os.Args[0])
	// log.Println(dir2)
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return
	}
	// first, err := os.StartProcess(dir2, []string{dir2, "-d"}, &os.ProcAttr{})
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Println(first.Pid)
	// first.Wait()
	switch functionName {
	case "ssr":
		pid, status := Get(configPath)
		if status == true {
			log.Println("already have run at " + pid)
			return
		}
		cmd := exec.Command(executablePath, "-d", "ssr")
		cmd.Run()
		log.Println(cmd.Process.Pid)
		// time.Sleep(time.Duration(500) * time.Millisecond)
		pid, status = Get(configPath)
		if status == true {
			log.Println("start ssr at deamon(pid=" + pid + ") successful!")
		} else {
			log.Println("run ssr failed!")
		}
	case "http":
		argument := config.GetConfig(configPath)
		fmt.Println("http proxy address:" + argument["httpProxy"])
		cmd := exec.Command(executablePath, "-sd", "httpB")
		// cmd.Run()
		cmd.Start()
		log.Println(cmd.Process.Pid)
		time.Sleep(time.Duration(500) * time.Millisecond)
		cmd.Process.Kill()
		cmd.Wait()
	case "httpBp":
		argument := config.GetConfig(configPath)
		fmt.Println("http proxy address:" + argument["httpProxy"])
		cmd := exec.Command(executablePath, "-sd", "httpBBp")
		// cmd.Run()
		cmd.Start()
		log.Println(cmd.Process.Pid)
		time.Sleep(time.Duration(500) * time.Millisecond)
		cmd.Process.Kill()
		cmd.Wait()
	}
}
