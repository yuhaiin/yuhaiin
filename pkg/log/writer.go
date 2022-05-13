package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		log:   log.New(os.Stderr, "[log]: ", 0),
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
		f.removeOldFile()
		f.fileLock.Unlock()
	default:
	}

	f.fileLock.RLock()
	defer f.fileLock.RUnlock()
	if f.w == nil {
		f.w, err = os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil {
			f.log.Println(err)
			return 0, err
		}
	}

	return f.w.Write(p)
}

func (f *FileWriter) removeOldFile() {
	dir, filename := filepath.Split(f.path)
	files, err := os.ReadDir(dir)
	if err != nil {
		f.log.Println(err)
		return
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})

	logfiles := make([]string, 0, len(files))

	for _, file := range files {
		if file.Name() == filename || !strings.HasPrefix(file.Name(), filename) {
			continue
		}

		logfiles = append(logfiles, file.Name())
	}

	if len(logfiles) <= 5 {
		return
	}

	for _, name := range logfiles[:len(logfiles)-5] {
		if err = os.Remove(filepath.Join(dir, name)); err != nil {
			f.log.Printf("remove log file %s failed: %v\n", name, err)
			continue
		}

		f.log.Println("remove log file", name)
	}
}
