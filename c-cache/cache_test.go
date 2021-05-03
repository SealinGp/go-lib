package c_cache

import (
	"log"
	"testing"
)

type item struct {
	val string
}

func (i *item) MemSize() int {
	return len(i.val)
}

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
