package httpx

import (
	"net/netip"
	"sync"
	"time"
)

// RateLimiter is a small in-memory token bucket keyed by client IP. It is per
// process, which is fine for the single-instance Compose deployment.
type RateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[netip.Addr]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimiter(perMinute, burst int) *RateLimiter {
	return &RateLimiter{rate: float64(perMinute) / 60, burst: float64(burst), buckets: map[netip.Addr]*bucket{}, lastGC: time.Now()}
}

func (l *RateLimiter) Allow(ip *netip.Addr) bool {
	if ip == nil {
		return false
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	b, ok := l.buckets[*ip]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[*ip] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
