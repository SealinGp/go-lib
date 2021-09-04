package c_log

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
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

type TTLDay int

type CloseFunc func() error
type CLogOptions struct {
	Flag     int
	Path     string //file path /a/b/c.log
	LogLevel int
	TTLDays  TTLDay //log file survive days
}

const (
	LEVEL_INFO = iota
	LEVEL_ERR
)

const (
	DateLayout        = "2006-01-02"
	HourMinuteMLayout = "15:04:05"

	INFO_PREFIX = "[I]"
	ERR_PREFIX  = "[E]"

	TTLWeek  TTLDay = 7
	TTLMonth TTLDay = 30
	TTLYear  TTLDay = 365
)

var _ (io.Writer) = (*clog)(nil)

var (
	ErrFileNotExists = errors.New("file not exists")

	cl = &clog{}
)

type clog struct {
	path         string
	logLevel     int
	ttl          time.Duration
	lastcheckTTL time.Time

	outputFile *os.File
	sync.Mutex

	closed  atomic.Value
	closeCh chan struct{}
}

func Writer() io.Writer {
	return cl
}

/*
how to use:
cf := CLogInit(opt)
defer cf()
*/
func CLogInit(opt *CLogOptions) CloseFunc {
	if opt.Path == "" {
		return func() error {
			return ErrFileNotExists
		}
	}

	path, err := filepath.Abs(opt.Path)
	if err != nil {
		panic(err)
	}
	opt.Path = path

	if opt.LogLevel <= LEVEL_INFO {
		opt.LogLevel = LEVEL_INFO
	}

	if opt.TTLDays <= TTLWeek {
		opt.TTLDays = TTLWeek
	}

	cl.closeCh = make(chan struct{})
	cl.closed.Store(false)
	cl.path = opt.Path
	cl.logLevel = opt.LogLevel
	cl.ttl = time.Hour * 24 * time.Duration(opt.TTLDays)

	log.SetFlags(opt.Flag)
	log.SetOutput(cl)

	cl.operateFile(time.Now(), true)
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
separate log file
1.open new log file
2.delete soft link
3.create new soft line 新建软链接
4.set log new out put to new soft line
5.close old file desc, set new file desc
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

/*
delete over ttl log file
*/
func (c *clog) delTTLFile(now time.Time, isInit bool) {
	if !isInit && now.Sub(c.lastcheckTTL) < c.ttl {
		return
	}

	endTime := now.Add(c.ttl * -1)

	lastIndexSlash := strings.LastIndexByte(c.path, '/')
	fileRoot := c.path[:lastIndexSlash]
	fileName := c.path[lastIndexSlash+1:]

	delFiles := c.getBeforeTTLFiles(fileRoot, fileName, endTime)
	if len(delFiles) <= 0 {
		return
	}

	for _, name := range delFiles {
		delFilePath := fmt.Sprintf("%s/%s", fileRoot, name)
		err := os.Remove(delFilePath)
		if err != nil {
			E("delete ttl file failed. path:%s, err:%v", delFilePath, err)
		}
	}

	c.lastcheckTTL = now
}

func (c *clog) getBeforeTTLFiles(fileRoot, fileName string, endTime time.Time) []string {
	delFiles := make([]string, 0, 10)

	filepath.Walk(fileRoot, func(_ string, info fs.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}
		if !strings.Contains(info.Name(), fileName) {
			return nil
		}

		logFilePart := strings.Split(info.Name(), ".")
		if len(logFilePart) != 3 {
			return nil
		}

		dateStr := logFilePart[2]
		logTime, err := time.Parse(fmt.Sprintf("%s %s", DateLayout, HourMinuteMLayout), fmt.Sprintf("%s 23:59:59", dateStr))
		if err == nil && logTime.Before(endTime) {
			delFiles = append(delFiles, info.Name())
		}

		return nil
	})

	return delFiles
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

		c.operateFile(now, false)
		timer = time.NewTimer(getTodayEndSubNow(now))
	}
}

func (c *clog) operateFile(now time.Time, isInit bool) {
	c.separateFile(now)
	c.delTTLFile(now, isInit)
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
	return time.Until(todayEnd) + 1*time.Second
}
