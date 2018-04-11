package cache

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Noop struct{}

// Prefix adds a common prefix to all cache access
func (c *Noop) Prefix(p ...string) Cache {
	return c
}

// Clone creates a copy of the cache accessor.
// With the same prefix the cloned copy will operate the same way as the original
func (c *Noop) Clone() Cache {
	return &Noop{}
}

// Set stores the data into the cache for a given key.
// the expiration will be evaluated at Get time.
func (c *Noop) Set(data []byte, expire time.Duration, key ...string) error {
	return nil
}

// Get retrieves a cached value for a given key.
// It returns an error if the key is either expired or does not exist
func (c *Noop) Get(key ...string) ([]byte, error) {
	return nil, fmt.Errorf("key %s is not cached", strings.Join(key, "."))
}

// SetJSON stores the an object into the cache for a given key after encoding it in json.
// the expiration will be evaluated at Get time.
func (c *Noop) SetJSON(o interface{}, expire time.Duration, key ...string) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return c.Set(b, expire, key...)
}

// GetJSON retrieves a cached value for a given key and decodes it from json.
// It returns an error if the key is either expired or does not exist
func (c *Noop) GetJSON(o interface{}, key ...string) error {
	b, err := c.Get(key...)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, o)
}
