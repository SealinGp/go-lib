package c_cache

import (
	"fmt"
	"log"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"
)

type item struct {
	val string
}

func (i *item) MemSize() int {
	return len(i.val)
}

//go test -v -run=NewCCache
func TestNewCCache(t *testing.T) {
	c := NewCCache(&CCacheOpt{
		LimitMem:   1 * KB,
		BucketSize: 5,
	})

	key := "a"
	item1 := &item{
		val: "b",
	}
	_, ok := c.Get(key)
	if ok {
		t.Errorf("[E] get failed.")
		return
	}

	c.Set(key, item1)
	item2, ok := c.Get(key)
	if !ok {
		t.Errorf("[E] get failed.")
		return
	}
	i := item2.(*item)
	log.Printf("[I] test ok. key:%v, val:%v", key, i.val)
}

var (
	deleteCount int32 = 0
)

type deleteNum struct{}

func (d *deleteNum) OnDelete() {
	atomic.AddInt32(&deleteCount, 1)
}

//go test -v -run=NONE -bench=NewCCache -benchmem
func BenchmarkNewCCache(b *testing.B) {
	c := NewCCache(&CCacheOpt{
		LimitMem:   1 * KB,
		BucketSize: 5,
		Observer:   &deleteNum{},
	})

	rand.Seed(time.Now().Unix())

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ri := rand.Intn(1000)
			key := fmt.Sprintf("c-%v", ri)

			it := &item{val: fmt.Sprintf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%v", ri)}
			c.Set(key, it)
		}
	})

	cur := atomic.LoadInt32(&c.curMem)
	log.Printf("[I] current:%v, limit:%v, deleteCount:%v", cur, c.limitMem, deleteCount)
}
