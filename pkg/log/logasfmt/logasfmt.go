package logasfmt

import (
	"fmt"
	"io"
	"log"
	"os"
)

var l = log.New(os.Stdout, "", log.Lshortfile|log.LstdFlags)

func init() {
	log.SetFlags(log.Llongfile)
}

func SetOutput(w io.Writer) {
	l.SetOutput(w)
	log.SetOutput(w)
}

func Printf(s string, v ...interface{}) { l.Output(2, fmt.Sprintf(s, v...)) }

func Println(v ...interface{}) { l.Output(2, fmt.Sprintln(v...)) }
