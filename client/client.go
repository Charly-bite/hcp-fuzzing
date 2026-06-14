package client

import (
	"log"
	"net/http"
	"time"
)

// FuzzClient represents the core HTTP client with custom transport for connection pooling
type FuzzClient struct {
	HTTPClient  *http.Client
	RateLimiter *AdaptiveRateLimiter
}

// NewFuzzClient sets up HTTP connection pooling, keep-alive headers, and proxy rotation
func NewFuzzClient(rateLimiter *AdaptiveRateLimiter, proxyManager *ProxyManager) *FuzzClient {
	// Phase 1: Connection pooling with keep-alive
	transport := &http.Transport{
		MaxIdleConns:        100, // Maximum number of idle (keep-alive) connections across all hosts
		MaxIdleConnsPerHost: 100, // Maximum idle connections to keep open for a single host
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false, // Explicitly false to reuse connections
	}

	// Phase 3: Traffic distribution proxy rotation
	if proxyManager != nil {
		transport.Proxy = proxyManager.GetProxy
	}

	return &FuzzClient{
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second, // General request timeout
		},
		RateLimiter: rateLimiter,
	}
}

// Do executes an HTTP request, ensuring we apply rate limits, jitter, and analytics logging
func (fc *FuzzClient) Do(req *http.Request) (*http.Response, error) {
	if fc.RateLimiter != nil {
		if err := fc.RateLimiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	// Phase 2: Apply a realistic browser fingerprint to evasion detection
	ApplyRandomFingerprint(req)

	start := time.Now()
	resp, err := fc.HTTPClient.Do(req)
	duration := time.Since(start)

	// Phase 1: Request/response logging and analytics
	if err != nil {
		log.Printf("[ERROR] Request %s %s failed: %v", req.Method, req.URL.String(), err)
		return nil, err
	}

	log.Printf("[INFO] %s %s - Status: %d - Time: %v - ContentLength: %d",
		req.Method, req.URL.String(), resp.StatusCode, duration, resp.ContentLength)

	return resp, nil
}
