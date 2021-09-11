package logasfmt

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

	fileLock sync.RWMutex
}

func NewLogWriter(file string) *FileWriter {
	return &FileWriter{
		path:  file,
		timer: time.NewTicker(time.Second),
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
		f.timer.Stop()
		f.timer.Reset(time.Hour)
		fs, err := os.Stat(f.path)
		if err != nil {
			log.Println(err)
			break
		}

		if fs.Size() < 1024*1024 {
			break
		}

		f.fileLock.Lock()
		if f.w != nil {
			f.w.Close()
			f.w = nil
		}

		err = os.Rename(f.path, fmt.Sprintf("%s_%d", f.path, time.Now().Unix()))
		if err != nil {
			log.Println(err)
		}
		f.fileLock.Unlock()
	default:
	}

	f.fileLock.RLock()
	defer f.fileLock.RUnlock()
	if f.w == nil {
		f.w, err = os.OpenFile(filepath.Join(f.path), os.O_APPEND|os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil {
			return 0, err
		}
	}

	return f.w.Write(p)
}
