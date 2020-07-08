package process

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func getSsr(path string) {
	file := path + "/shadowsocksr.zip" //源文件路径
	url := "https://github.com/asutorufg/shadowsocksr/archive/asutorufg.zip"
	fmt.Println("Downloading shadowsocksr.zip")
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	f, err := os.Create(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, _ = io.Copy(f, res.Body)
}

func unzipSsr(path string) {
	// 打开一个zip格式文件
	r, err := zip.OpenReader(path + "/shadowsocksr.zip")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer r.Close()
	var unzipName string
	for num, k := range r.Reader.File {
		if k.FileInfo().IsDir() {
			if num == 0 {
				unzipName = "/" + k.Name
			}
			err := os.MkdirAll(path+"/"+k.Name, 0755)
			if err != nil {
				fmt.Println(err)
			}
			continue
		}
		r, err := k.Open()
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println("unzip: ", k.Name)
		NewFile, err := os.Create(path + "/" + k.Name)
		if err != nil {
			fmt.Println(err)
			continue
		}
		_, _ = io.Copy(NewFile, r)
		_ = NewFile.Close()
	}

	err = os.Rename(path+unzipName, path+"/shadowsocksr")
	if err != nil {
		log.Println(err)
		return
	}
}

func GetSsrPython(path string) {
	getSsr(path)
	unzipSsr(path)

	err := os.Remove(path + "/shadowsocksr.zip")
	if err != nil {
		log.Fatalf("GetSsrPython -> %v", err)
	}
}
