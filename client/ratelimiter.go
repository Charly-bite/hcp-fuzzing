package client

import (
	"context"
	"math/rand"
	"time"

	"golang.org/x/time/rate"
)

// AdaptiveRateLimiter controls request frequency and injects jitter
type AdaptiveRateLimiter struct {
	limiter   *rate.Limiter
	minJitter time.Duration
	maxJitter time.Duration
}

// NewAdaptiveRateLimiter creates a new rate limiter using token bucket algorithm.
// reqPerSec controls the max burst and steady rate.
func NewAdaptiveRateLimiter(reqPerSec float64, minJitter, maxJitter time.Duration) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		// Allow limit per second with a bucket capacity matching the req/s
		limiter:   rate.NewLimiter(rate.Limit(reqPerSec), int(reqPerSec+1)),
		minJitter: minJitter,
		maxJitter: maxJitter,
	}
}

// Wait blocks until a request is permitted, and applies random jitter.
func (rl *AdaptiveRateLimiter) Wait(ctx context.Context) error {
	// 1. Token Bucket Control
	err := rl.limiter.Wait(ctx)
	if err != nil {
		return err
	}

	// 2. Jitter Injection (randomization between minJitter and maxJitter)
	if rl.maxJitter > rl.minJitter {
		jitter := time.Duration(rand.Int63n(int64(rl.maxJitter-rl.minJitter))) + rl.minJitter
		select {
		case <-time.After(jitter):
			// Proceed
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
