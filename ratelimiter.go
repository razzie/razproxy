package razproxy

import (
	"sync"

	"golang.org/x/time/rate"
)

type rateLimiter struct {
	ips map[string]*rate.Limiter
	mtx sync.RWMutex
	r   rate.Limit
	b   int
}

func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	return &rateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

func (r *rateLimiter) get(ip string) *rate.Limiter {
	r.mtx.RLock()
	limiter, ok := r.ips[ip]
	r.mtx.RUnlock()

	if !ok {
		limiter = rate.NewLimiter(r.r, r.b)
		r.mtx.Lock()
		r.ips[ip] = limiter
		r.mtx.Unlock()
	}

	return limiter
}
