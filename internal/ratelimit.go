package internal

import (
	"sync"
	"time"
)

// TokenBucket implements a simple in-memory rate limiter.
type TokenBucket struct {
	capacity int
	tokens   int
	refill   time.Duration
	last     time.Time
	mu       sync.Mutex
}

func NewTokenBucket(capacity int, refill time.Duration) *TokenBucket {
	return &TokenBucket{
		capacity: capacity,
		tokens:   capacity,
		refill:   refill,
		last:     time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.last)
	if elapsed >= tb.refill {
		tb.tokens = tb.capacity
		tb.last = now
	}
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}
	return false
}

func (tb *TokenBucket) Tokens() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens
}
