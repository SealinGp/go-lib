package c_cache

import (
	"container/list"
	"hash/fnv"
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

type Observer interface {
	OnDelete()
}

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
	observer Observer
}

type CCacheOpt struct {
	LimitMem   MemUnit
	BucketSize int
	Observer   Observer
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
		observer: opt.Observer,
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
	bucket.RUnlock()
	if !ok {
		return nil, false
	}

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
			oldEntry.value = val
			bucket.lruList.MoveToFront(curEle)
			atomic.AddInt32(&c.curMem, int32(diffSize))
			return
		}

		newMem = diffSize
		newEntry = oldEntry
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

		if c.observer != nil {
			c.observer.OnDelete()
		}
	}

	curEle, ok = bucket.entries[key]
	if ok {
		curEle.Value = newEntry
		bucket.lruList.MoveToFront(curEle)
	} else {
		ele := bucket.lruList.PushFront(newEntry)
		bucket.entries[key] = ele
	}
	atomic.AddInt32(&c.curMem, int32(newMem))
}
