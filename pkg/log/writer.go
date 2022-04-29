package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var _ io.Writer = new(FileWriter)

type FileWriter struct {
	path  string
	timer *time.Ticker
	w     *os.File
	log   *log.Logger

	fileLock sync.RWMutex
}

func NewLogWriter(file string) *FileWriter {
	return &FileWriter{
		path:  file,
		timer: time.NewTicker(1),
		log:   log.New(os.Stderr, "log", 0),
	}
}

func (f *FileWriter) Close() error {
	if f.timer != nil {
		f.timer.Stop()
	}

	if f.w != nil {
		return f.w.Close()
	}

	return nil
}

func (f *FileWriter) Write(p []byte) (n int, err error) {
	select {
	case <-f.timer.C:
		f.timer.Reset(time.Hour)
		fs, err := os.Stat(f.path)
		if err != nil {
			f.log.Println(err)
			break
		}

		if fs.Size() < 1024*1024 {
			f.log.Println("checked logs' file is not over 1 MB, break")
			break
		}

		f.log.Println("checked logs' file over 1 MB, rename old logs")

		f.fileLock.Lock()
		if f.w != nil {
			f.w.Close()
			f.w = nil
		}

		err = os.Rename(f.path, fmt.Sprintf("%s_%d", f.path, time.Now().Unix()))
		if err != nil {
			f.log.Println(err)
		}
		f.fileLock.Unlock()
	default:
	}

	f.fileLock.RLock()
	defer f.fileLock.RUnlock()
	if f.w == nil {
		f.w, err = os.OpenFile(filepath.Join(f.path), os.O_APPEND|os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil {
			f.log.Println(err)
			return 0, err
		}
	}

	return f.w.Write(p)
}
