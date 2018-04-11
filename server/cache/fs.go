package cache

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// FileSystemCache is a cache that writes the content to the file system
type FileSystemCache struct {
	path   string
	prefix []string
}

// NewFileSystemCache instanciates a cache backed on the file system
func NewFileSystemCache(path string) *FileSystemCache {
	return &FileSystemCache{
		path: path,
	}
}

// Prefix adds a common prefix to all cache access
func (c *FileSystemCache) Prefix(p ...string) Cache {
	c.prefix = p
	return c
}

// Clone creates a copy of the cache accessor.
// With the same prefix the cloned copy will operate the same way as the original
func (c *FileSystemCache) Clone() Cache {
	return &FileSystemCache{
		path:   path.Join(append([]string{c.path}, c.prefix...)...),
		prefix: []string{},
	}
}

// Set stores the data into the cache for a given key.
// the expiration will be evaluated at Get time.
func (c *FileSystemCache) Set(data []byte, expire time.Duration, key ...string) error {
	if len(key) < 1 {
		return fmt.Errorf("no key specified")
	}
	folder := c.keyPath(key[:len(key)-1]...)
	_, err := os.Stat(folder)
	if os.IsNotExist(err) {
		os.MkdirAll(folder, 0700)
	}
	if expire > 0 {
		expireTS := time.Now().Add(expire).UnixNano()
		err := ioutil.WriteFile(c.expirePath(key...), []byte(strconv.FormatInt(expireTS, 10)), 0600)
		if err != nil {
			return err
		}
	}
	return ioutil.WriteFile(c.keyPath(key...), data, 0600)
}

// Get retrieves a cached value for a given key.
// It returns an error if the key is either expired or does not exist
func (c *FileSystemCache) Get(key ...string) ([]byte, error) {
	if len(key) < 1 {
		return nil, fmt.Errorf("no key specified")
	}
	_, err := os.Stat(c.expirePath(key...))
	if !os.IsNotExist(err) {
		d, err := ioutil.ReadFile(c.expirePath(key...))
		if err != nil {
			return nil, fmt.Errorf("failed to get expiration time")
		}
		ts, err := strconv.ParseInt(string(d), 10, 0)
		if ts < time.Now().UnixNano() {
			return nil, fmt.Errorf("key %s expired at timestamp %d. current timestamp: %d", strings.Join(key, "."), ts, time.Now().Unix())
		}
	}
	return ioutil.ReadFile(c.keyPath(key...))
}

// SetJSON stores the an object into the cache for a given key after encoding it in json.
// the expiration will be evaluated at Get time.
func (c *FileSystemCache) SetJSON(o interface{}, expire time.Duration, key ...string) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return c.Set(b, expire, key...)
}

// GetJSON retrieves a cached value for a given key and decodes it from json.
// It returns an error if the key is either expired or does not exist
func (c *FileSystemCache) GetJSON(o interface{}, key ...string) error {
	b, err := c.Get(key...)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, o)
}

func (c *FileSystemCache) keyPath(key ...string) string {
	return path.Join(append(append([]string{c.path}, c.prefix...), key...)...)
}

func (c *FileSystemCache) expirePath(key ...string) string {
	return c.keyPath(key...) + ".expire"
}
