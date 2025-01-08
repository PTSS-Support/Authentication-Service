package cache

import (
	"sync"
	"time"
)

type TokenCache interface {
	GetValidToken() (string, bool)
	SetToken(token string, expiresIn int)
	IsValid() bool
}

type tokenCache struct {
	token     string
	expiresAt time.Time
	mutex     sync.RWMutex
}

func NewTokenCache() TokenCache {
	return &tokenCache{}
}

func (c *tokenCache) GetValidToken() (string, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.IsValid() {
		return c.token, true
	}
	return "", false
}

func (c *tokenCache) IsValid() bool {
	return c.token != "" && time.Now().Before(c.expiresAt)
}

func (c *tokenCache) SetToken(token string, expiresIn int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	bufferTime := 30 * time.Second
	c.token = token
	c.expiresAt = time.Now().Add(time.Duration(expiresIn)*time.Second - bufferTime)
}
