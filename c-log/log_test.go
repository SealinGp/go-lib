package c_log

import (
	"log"
	"sync"
	"testing"
)

//not use
func TestCLogInit(t *testing.T) {
	cf := CLogInit(&CLogOptions{
		Flag: log.Ltime | log.Lshortfile,
		Path: "",
	})

	log.Printf("[E] xxx ...")

	defer cf()
}

//use file and level
func TestCLogInit1(t *testing.T) {
	//not use
	cf := CLogInit(&CLogOptions{
		Flag:     log.Ltime | log.Lshortfile,
		Path:     "./test.log",
		LogLevel: LEVEL_ERR,
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		I("info log. x:v, a:%v", "b")
	}()
	go func() {
		defer wg.Done()
		E("nihao xxx. x:v, a:%v", "b")
	}()
	defer cf()

	wg.Wait()
}
