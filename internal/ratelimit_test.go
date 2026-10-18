package internal

import (
	"testing"
	"time"
)

func TestTokenBucketBurst(t *testing.T) {
	tb := NewTokenBucket(5, time.Second)
	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Fatalf("request %d should be allowed (burst)", i+1)
		}
	}
	if tb.Allow() {
		t.Fatal("6th request should be denied")
	}
}

func TestTokenBucketRefill(t *testing.T) {
	tb := NewTokenBucket(2, 50*time.Millisecond)
	_ = tb.Allow()
	_ = tb.Allow()
	if tb.Allow() {
		t.Fatal("should be empty")
	}
	time.Sleep(60 * time.Millisecond)
	if !tb.Allow() {
		t.Fatal("should refill after interval")
	}
}
