package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoop(t *testing.T) {
	cache := &Noop{}
	cache.Clone().Prefix("bla")
	assert.NoError(t, cache.Set([]byte{}, 0, "some", "key"))
	b, err := cache.Get("some", "key")
	assert.Error(t, err)
	assert.Nil(t, b)
}
