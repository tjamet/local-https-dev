package cache

import (
	"time"
)

// Cache defines the interface to implement to handle acme results caching
type Cache interface {
	Get(key ...string) ([]byte, error)
	Set(data []byte, expire time.Duration, key ...string) error
	SetJSON(o interface{}, expire time.Duration, key ...string) error
	GetJSON(o interface{}, key ...string) error
	Clone() Cache
	Prefix(key ...string) Cache
}
