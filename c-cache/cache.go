package c_cache

import (
	"container/list"
	"hash/fnv"
	"log"
	"sync"
	"sync/atomic"
)

type MemUnit int

const Unit = 1 << 10

const (
	Byte MemUnit = iota + 1
	KB           = Byte * Unit
	MB           = KB * Unit
	GB           = MB * Unit
)

type Value interface {
	MemSize() int
}

/**
ccache: customize cache
limitMem: 1*MB, 1*KB, 1*GB...
buckets: default 1
*/

type CCache struct {
	curMem   int32
	limitMem MemUnit
	buckets  []*bucket
}

type CCacheOpt struct {
	LimitMem   MemUnit
	BucketSize int
}

type bucket struct {
	lruList *list.List
	entries map[string]*list.Element
	sync.RWMutex
}

type entry struct {
	key   string
	value Value
}

func NewCCache(opt *CCacheOpt) *CCache {
	if opt.LimitMem <= KB {
		opt.LimitMem = KB
	}
	if opt.BucketSize <= 0 {
		opt.BucketSize = 1
	}

	ccache := &CCache{
		curMem:   0,
		limitMem: opt.LimitMem,
		buckets:  make([]*bucket, opt.BucketSize),
	}

	for i := 0; i < opt.BucketSize; i++ {
		ccache.buckets[i] = &bucket{
			lruList: list.New(),
			entries: make(map[string]*list.Element),
		}
	}

	return ccache
}

func (c *CCache) hash(key string) int {
	h := fnv.New32()
	h.Write([]byte(key))
	return int(h.Sum32() % uint32(len(c.buckets)))
}

func (c *CCache) Get(key string) (Value, bool) {
	index := c.hash(key)
	bucket := c.buckets[index]

	bucket.RLock()
	curEle, ok := bucket.entries[key]
	if !ok {
		bucket.RUnlock()
		return nil, false
	}
	bucket.RUnlock()

	bucket.Lock()
	bucket.lruList.MoveToFront(curEle)
	bucket.Unlock()

	e := curEle.Value.(*entry)
	return e.value, true
}

func (c *CCache) Set(key string, val Value) {
	index := c.hash(key)
	bucket := c.buckets[index]

	newEntry := &entry{
		key:   key,
		value: val,
	}
	newMem := len(key) + val.MemSize()

	bucket.Lock()
	defer bucket.Unlock()

	curEle, ok := bucket.entries[key]
	if ok {
		oldEntry := curEle.Value.(*entry)
		diffSize := val.MemSize() - oldEntry.value.MemSize()
		if diffSize <= 0 {
			curEle.Value = val
			atomic.AddInt32(&c.curMem, int32(diffSize))
			return
		}

		newMem = diffSize
	}

	curMem := atomic.LoadInt32(&c.curMem)
	for int(curMem)+newMem > int(c.limitMem) {
		lastEle := bucket.lruList.Back()
		if lastEle == nil {
			return
		}

		lastEntry := lastEle.Value.(*entry)
		delta := lastEntry.value.MemSize() + len(lastEntry.key)

		bucket.lruList.Remove(lastEle)
		delete(bucket.entries, lastEntry.key)

		curMem = atomic.AddInt32(&c.curMem, -int32(delta))
	}

	log.Printf("??")

	curEle, ok = bucket.entries[key]
	if ok {
		curEle.Value = newEntry
		bucket.lruList.MoveToFront(curEle)
	} else {
		ele := &list.Element{Value: newEntry}
		bucket.entries[key] = ele
		bucket.lruList.PushFront(ele)
	}
	atomic.AddInt32(&c.curMem, int32(newMem))
}
