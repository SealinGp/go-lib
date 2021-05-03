package c_log

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/**
c_log: customize log , rotate by day

example:
xx.log -> xx.log.2021-04-11
xx.log.2021-04-11
xx.log.2021-04-10

log level
info = 0
warning = 1
error = 2
>= info     info,warning,error
>= warning  warning,error
>= error    error
*/

const (
	LEVEL_INFO = iota
	LEVEL_ERR
)

const (
	DateLayout        = "2006-01-02"
	HourMinuteMLayout = "15:04:05"

	INFO_PREFIX = "[I]"
	ERR_PREFIX  = "[E]"
)

var (
	ErrFileNotExists = errors.New("file not exists")

	cl = &clog{}
)

func CLogInit(opt *CLogOptions) CloseFunc {
	if opt.Path == "" {
		return func() error {
			return ErrFileNotExists
		}
	}

	if opt.LogLevel <= LEVEL_INFO {
		opt.LogLevel = LEVEL_INFO
	}

	cl.closeCh = make(chan struct{})
	cl.closed.Store(false)
	cl.path = opt.Path
	cl.logLevel = opt.LogLevel

	log.SetFlags(opt.Flag)
	log.SetOutput(cl)

	cl.separateFile(time.Now())
	go cl.serve()
	return func() error {
		if closedBool, ok := cl.closed.Load().(bool); !ok || closedBool {
			return nil
		}

		close(cl.closeCh)
		cl.closed.Store(true)
		return nil
	}
}

/**
E for error
I for info
*/
func E(format string, v ...interface{}) {
	format = fmt.Sprintf("%v %v", ERR_PREFIX, format)
	log.Printf(format, v...)
}

func I(format string, v ...interface{}) {
	format = fmt.Sprintf("%v %v", INFO_PREFIX, format)
	log.Printf(format, v...)
}

type CLogOptions struct {
	Flag     int
	Path     string
	LogLevel int
}

type CloseFunc func() error

type clog struct {
	path     string
	logLevel int

	outputFile *os.File
	sync.Mutex

	closed  atomic.Value
	closeCh chan struct{}
}

func (c *clog) Write(p []byte) (n int, err error) {
	if c.logLevel >= LEVEL_ERR {
		if !strings.Contains(string(p), ERR_PREFIX) {
			return 0, nil
		}
	}

	c.Lock()
	defer c.Unlock()
	return c.outputFile.Write(p)
}

func (c *clog) SetOutput(fd *os.File) {
	c.Lock()
	defer c.Unlock()

	if c.outputFile != nil {
		_ = c.outputFile.Close()
	}
	c.outputFile = fd
}

/**
1.打开新文件
2.删除软链接
3.新建软链接
4.设置日志新输出
5.关闭旧日志文件描述符,设置新日志文件描述符
*/
func (c *clog) separateFile(now time.Time) {
	//打开文件
	dateFilePath := fmt.Sprintf("%v.%v", c.path, now.Format(DateLayout))
	dateFileDesc, err := os.OpenFile(dateFilePath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0755)
	if err != nil {
		panic(err)
	}

	//删除软链接
	err = os.Remove(cl.path)
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}

	//指向软链接
	err = os.Symlink(dateFilePath, c.path)
	if err != nil {
		panic(err)
	}

	//设置输出
	c.SetOutput(dateFileDesc)
}

func (c *clog) serve() {
	now := time.Now()

	todayEndDur := getTodayEndSubNow(now)
	timer := time.NewTimer(todayEndDur)
	defer timer.Stop()

	for {
		select {
		case <-c.closeCh:
			return
		case now = <-timer.C:
		}

		c.separateFile(now)
		timer = time.NewTimer(getTodayEndSubNow(now))
	}
}

/*
calculate the duration of now sub end of today
duration = now - Y-M-D 23:59:59

example:
now = 2021-04-11 09:55:00
duration = (2021-04-11 23:99:99 - 2021-04-11 09:55:00) + 1s
*/
func getTodayEndSubNow(now time.Time) time.Duration {
	nowStr := now.Format("2006-01-02 15:04:05")
	spaceIndex := strings.Index(nowStr, " ")
	nowStr = nowStr[:spaceIndex]

	nowStr = fmt.Sprintf("%v 23:59:59", nowStr)
	todayEnd, _ := time.Parse("2006-01-02 15:04:05", nowStr)
	return todayEnd.Sub(time.Now()) + 1*time.Second
}
