package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var _ io.Writer = new(FileWriter)

type FileWriter struct {
	path logPath
	w    *os.File
	log  *slog.Logger

	mu sync.RWMutex

	savedSize atomic.Uint64
}

func NewLogWriter(file string) *FileWriter {
	return &FileWriter{
		path: NewPath(file),
		log: slog.New(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug})),
	}
}

func (f *FileWriter) Close() error {
	if f.w != nil {
		return f.w.Close()
	}

	return nil
}

func (f *FileWriter) Write(p []byte) (n int, err error) {
	if f.w == nil {
		f.mu.Lock()
		f.w, err = os.OpenFile(f.path.FullPath(""), os.O_APPEND|os.O_CREATE|os.O_RDWR, os.ModePerm)
		f.mu.Unlock()

		if err != nil {
			f.log.Error("open file failed:", "err", err)
			return 0, err
		}

		f.mu.RLock()
		stat, err := f.w.Stat()
		if err == nil {
			f.savedSize.Store(uint64(stat.Size()))
		}
		f.mu.RUnlock()
	}

	f.mu.RLock()
	n, err = f.w.Write(p)
	f.mu.RUnlock()

	if int(f.savedSize.Add(uint64(n))) >= maxSize {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.savedSize.Store(0)

		f.w.Close()
		f.w = nil

		err = os.Rename(f.path.FullPath(""),
			f.path.FullPath(strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", ".")))
		if err != nil {
			f.log.Error("rename file failed:", "err", err)
		}

		f.removeOldFile()
	}

	return n, err
}

func (f *FileWriter) removeOldFile() {
	files, err := os.ReadDir(f.path.dir)
	if err != nil {
		f.log.Error("read dir failed:", "err", err)
		return
	}

	if len(files) <= maxFile {
		return
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Name() > files[j].Name() })

	count := 0
	for _, file := range files {
		if !(strings.HasPrefix(file.Name(), f.path.base+"_") && strings.HasSuffix(file.Name(), f.path.ext)) {
			continue
		}

		count++

		if count <= maxFile {
			continue
		}

		name := filepath.Join(f.path.dir, file.Name())

		err = os.Remove(name)
		if err != nil {
			f.log.Error("remove log file failed:", "file", name, "err", err)
		} else {
			f.log.Debug("remove log file", "file", name)
		}
	}

}

type logPath struct {
	ext  string
	base string
	dir  string
}

func NewPath(path string) logPath {
	dir := filepath.Dir(path)
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(filepath.Base(path), ext)

	return logPath{ext, base, dir}
}

func (l logPath) FullPath(suffix string) string {
	if suffix != "" {
		suffix = "_" + suffix
	}

	return filepath.Join(l.dir, fmt.Sprint(l.base, suffix, l.ext))
}

func (l *logPath) FullName(suffix string) string { return fmt.Sprint(l.base, suffix, l.ext) }
