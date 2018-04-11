package cache

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetReturnsCorrectValue(t *testing.T) {
	cache := NewFileSystemCache("./resources").Prefix("base")
	checkCacheValue(t, "cached value", cache, "key")
}

func TestCloneFreezesPrefix(t *testing.T) {
	cache := NewFileSystemCache("test").Prefix("somePrefix").Clone().(*FileSystemCache)
	assert.Equal(t, "test/somePrefix", cache.path)
	assert.Equal(t, []string{}, cache.prefix)
}

func TestGetExpiredReturnsError(t *testing.T) {
	cache := NewFileSystemCache("./resources")
	checkCacheMissing(t, cache, "expired")
}

func TestSetStoresGettableValue(t *testing.T) {
	dir, err := ioutil.TempDir("", "example")
	assert.NoError(t, err)

	defer os.RemoveAll(dir)
	fmt.Println(dir)

	cache := NewFileSystemCache(dir)
	assert.NoError(t, cache.Set([]byte("hello world"), 0, "some", "key"))
	checkCacheValue(t, "hello world", cache, "some", "key")
	checkCacheMissing(t, cache, "some", "key2")
	assert.NoError(t, cache.Set([]byte("hello world"), 10*time.Millisecond, "some", "key2"))
	checkCacheValue(t, "hello world", cache, "some", "key2")
	time.Sleep(20 * time.Millisecond)
	checkCacheMissing(t, cache, "some", "key2")
}

func TestGetWithoutKeyReturnsAnError(t *testing.T) {
	_, err := NewFileSystemCache("./resources").Get()
	assert.Error(t, err)
}

func TestSetWithoutKeyReturnsAnError(t *testing.T) {
	assert.Error(t, NewFileSystemCache("./resources").Set([]byte{}, 0))
}

func checkCacheValue(t testing.TB, expected string, cache Cache, key ...string) {
	value, err := cache.Get(key...)
	assert.NoError(t, err)
	assert.Equal(t, expected, string(value))
}

func checkCacheMissing(t testing.TB, cache Cache, key ...string) {
	value, err := cache.Get(key...)
	assert.Error(t, err)
	assert.Equal(t, "", string(value))
}
