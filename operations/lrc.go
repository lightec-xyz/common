package operations

import (
	"container/list"
	"fmt"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"sync"
)

var lruManager *LruManager

func InitLru(capacity int) {
	lruManager = NewLruManager(capacity)
}

type LruManager struct {
	pkQueue  *LRUCache // path -> ProvingKey
	vkQueue  *LRUCache // path -> VerifyingKey
	cssQueue *LRUCache // path -> css
}

func NewLruManager(capacity int) *LruManager {
	return &LruManager{
		pkQueue:  NewLRUCache(capacity),
		vkQueue:  NewLRUCache(capacity),
		cssQueue: NewLRUCache(capacity),
	}
}

func (m *LruManager) GetPk(path string) (plonk.ProvingKey, error) {
	value, ok := m.pkQueue.Get(path)
	if ok {
		return value.(plonk.ProvingKey), nil
	}
	pk, err := ReadPk(path)
	if err != nil {
		return nil, err
	}
	m.pkQueue.Put(path, pk)
	return pk, nil
}

func (m *LruManager) GetVk(path string) (plonk.VerifyingKey, error) {
	value, ok := m.vkQueue.Get(path)
	if ok {
		return value.(plonk.VerifyingKey), nil
	}
	vk, err := ReadVk(path)
	if err != nil {
		return nil, err
	}
	m.vkQueue.Put(path, vk)
	return vk, nil
}

func (m *LruManager) GetCcs(path string) (constraint.ConstraintSystem, error) {
	value, ok := m.cssQueue.Get(path)
	if ok {
		return value.(constraint.ConstraintSystem), nil
	}
	ccs, err := ReadCcs(path)
	if err != nil {
		return nil, err
	}
	m.cssQueue.Put(path, ccs)
	return ccs, nil
}

type LRUCache struct {
	capacity int
	cache    map[string]*list.Element
	list     *list.List
	lock     sync.Mutex
}

type Element struct {
	key   string
	value interface{}
}

func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (l *LRUCache) Get(key string) (interface{}, bool) {
	defer l.lock.Unlock()
	l.lock.Lock()
	if element, ok := l.cache[key]; ok {
		l.list.MoveToFront(element)
		return element.Value.(*Element).value, true
	}
	return nil, false
}

func (l *LRUCache) Put(key string, value interface{}) {
	defer l.lock.Unlock()
	l.lock.Lock()
	if element, ok := l.cache[key]; ok {
		element.Value.(*Element).value = value
		l.list.MoveToFront(element)
		return
	}
	if len(l.cache) >= l.capacity {
		backElement := l.list.Back()
		if backElement != nil {
			delete(l.cache, backElement.Value.(*Element).key)
			l.list.Remove(backElement)
			backElement.Value = nil // careful release pointer
		}
	}
	newElement := l.list.PushFront(&Element{key, value})
	l.cache[key] = newElement
}

func (l *LRUCache) Display() {
	for e := l.list.Front(); e != nil; e = e.Next() {
		fmt.Printf("[%s: %s] ", e.Value.(*Element).key, e.Value.(*Element).value)
	}
	fmt.Println()
}
