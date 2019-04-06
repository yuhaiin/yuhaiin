package SsrDownload

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
)

func Get_ssr(path string) {
	file := path + "/shadowsocksr.zip" //源文件路径
	os.Remove(file)                    //删除文件test.txt
	url := "https://github.com/asutorufg/shadowsocksr/archive/asutorufg.zip"
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	f, err := os.Create(file)
	if err != nil {
		panic(err)
	}
	io.Copy(f, res.Body)
}

func Unzip_ssr(path string) {
	// 打开一个zip格式文件
	r, err := zip.OpenReader(path + "/桌面/shadowsocksr.zip")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, k := range r.Reader.File {
		if k.FileInfo().IsDir() {
			err := os.MkdirAll(k.Name, 0755)
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
		defer r.Close()
		NewFile, err := os.Create(k.Name)
		if err != nil {
			fmt.Println(err)
			continue
		}
		io.Copy(NewFile, r)
		NewFile.Close()
	}
}
