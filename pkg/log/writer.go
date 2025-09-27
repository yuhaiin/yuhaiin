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

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var _ io.Writer = new(FileWriter)

type FileWriter struct {
	w   *os.File
	log *slog.Logger

	path logPath

	savedSize atomic.Int64

	cycleSign syncmap.SyncMap[chan struct{}, struct{}]

	mu sync.RWMutex

	removeOldFileMu sync.Mutex
}

func NewLogWriter(file string) *FileWriter {
	return &FileWriter{
		path: NewPath(file),
		log: slog.New(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug})),
	}
}

func (f *FileWriter) NewCycleSign() chan struct{} {
	c := make(chan struct{}, 1)
	f.cycleSign.Store(c, struct{}{})
	return c
}

func (f *FileWriter) RemoveCycleSign(c chan struct{}) {
	f.cycleSign.Delete(c)
}

func (f *FileWriter) Close() error {
	if f.w != nil {
		return f.w.Close()
	}

	return nil
}

func (f *FileWriter) initWriter() (io.Writer, error) {
	f.mu.RLock()
	w := f.w
	f.mu.RUnlock()

	if w != nil {
		return w, nil
	}

	f.mu.Lock()

	if f.w != nil {
		return f.w, nil
	}

	var err error
	w, err = os.OpenFile(f.path.FullPath(""), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	f.w = w
	f.cycleSign.Range(func(key chan struct{}, value struct{}) bool {
		select {
		case key <- struct{}{}:
		default:
		}
		return true
	})
	f.mu.Unlock()

	if err != nil {
		f.log.Error("open file failed:", "err", err)
		return nil, err
	}

	f.mu.RLock()
	stat, err := f.w.Stat()
	if err == nil {
		f.savedSize.Store(int64(stat.Size()))
	}
	f.mu.RUnlock()

	return w, nil
}

func (f *FileWriter) cycleNewFile() {
	f.mu.Lock()
	defer f.mu.Unlock()

	if int(f.savedSize.Load()) < configuration.LogNaxSize {
		return
	}

	f.savedSize.Store(0)

	_ = f.w.Close()
	f.w = nil

	err := os.Rename(f.path.FullPath(""), f.path.FullPath(time.Now().Format("2006-01-02T15.04.05Z0700")))
	if err != nil {
		f.log.Error("rename file failed:", "err", err)
	}

	go f.removeOldFile()
}

func (f *FileWriter) Write(p []byte) (n int, err error) {
	w, err := f.initWriter()
	if err != nil {
		return
	}

	n, err = w.Write(p)

	if int(f.savedSize.Add(int64(n))) >= configuration.LogNaxSize {
		f.cycleNewFile()
	}

	return n, err
}

func (f *FileWriter) removeOldFile() {
	f.removeOldFileMu.Lock()
	defer f.removeOldFileMu.Unlock()

	files, err := os.ReadDir(f.path.dir)
	if err != nil {
		f.log.Error("read dir failed:", "err", err)
		return
	}

	if len(files) <= configuration.LogMaxFile {
		return
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Name() > files[j].Name() })

	count := 0
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), f.path.base+"_") || !strings.HasSuffix(file.Name(), f.path.ext) {
			continue
		}

		count++

		if count <= configuration.LogMaxFile {
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
