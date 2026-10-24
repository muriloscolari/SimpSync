package handlers

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxTrackedIPs = 4096

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

type RateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	ratePerSec  float64
	burst       float64
	ttl         time.Duration
	lastSweepAt time.Time
}

func NewRateLimiter(ratePerMinute float64, burst int, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:     make(map[string]*bucket),
		ratePerSec:  ratePerMinute / 60.0,
		burst:       float64(burst),
		ttl:         ttl,
		lastSweepAt: time.Now(),
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if now.Sub(rl.lastSweepAt) > rl.ttl || len(rl.buckets) >= maxTrackedIPs {
		for k, b := range rl.buckets {
			if now.Sub(b.lastSeen) > rl.ttl {
				delete(rl.buckets, k)
			}
		}
		// Hard cap protection: if still at capacity after TTL sweep, drop one arbitrary entry.
		if len(rl.buckets) >= maxTrackedIPs {
			for k := range rl.buckets {
				delete(rl.buckets, k)
				break
			}
		}
		rl.lastSweepAt = now
	}

	b, exists := rl.buckets[key]
	if !exists {
		rl.buckets[key] = &bucket{
			tokens:   rl.burst - 1,
			lastSeen: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.ratePerSec
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
	}
	b.lastSeen = now
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func clientIP(r *http.Request, trustLoopbackProxy bool) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if trustLoopbackProxy && ip != nil && ip.IsLoopback() {
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			if parsed := net.ParseIP(realIP); parsed != nil {
				return parsed.String()
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if parsed := net.ParseIP(first); parsed != nil {
				return parsed.String()
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	return host
}
