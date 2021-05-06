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
func TestCLogLevel(t *testing.T) {
	//not use
	cf := CLogInit(&CLogOptions{
		Flag:     log.Ltime | log.Lshortfile,
		Path:     "./test.log",
		LogLevel: LEVEL_INFO,
	})

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		I("info log. x:v, a:%v", "b")
	}()
	go func() {
		defer wg.Done()
		E("nihao xxx. x:v, a:%v", "b")
	}()
	go func() {
		defer wg.Done()
		log.Printf("normal log xx. a:a1, b:%v","b1")
	}()
	defer cf()

	wg.Wait()
}
