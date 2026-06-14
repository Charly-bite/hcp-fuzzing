package client

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"sync/atomic"
)

// ProxyManager handles proxy rotation for the distribution layer
type ProxyManager struct {
	proxies []*url.URL
	counter uint64
}

// NewProxyManager parses a list of proxy URLs and returns a ProxyManager
func NewProxyManager(proxyList []string) (*ProxyManager, error) {
	if len(proxyList) == 0 {
		return nil, errors.New("proxy list cannot be empty")
	}

	var parsedProxies []*url.URL
	for _, p := range proxyList {
		u, err := url.Parse(p)
		if err != nil {
			return nil, err
		}
		parsedProxies = append(parsedProxies, u)
	}

	return &ProxyManager{
		proxies: parsedProxies,
	}, nil
}

// GetProxy returns the next proxy in a round-robin fashion.
// This signature matches the http.Transport.Proxy function definition.
func (pm *ProxyManager) GetProxy(req *http.Request) (*url.URL, error) {
	if len(pm.proxies) == 0 {
		return nil, nil
	}

	// Round-robin traffic distribution
	index := atomic.AddUint64(&pm.counter, 1) % uint64(len(pm.proxies))
	proxy := pm.proxies[index]

	log.Printf("[Phase 3] Routing request to %s via Proxy: %s", req.URL.Host, proxy.String())

	// For lab environments without actual proxies running on these ports,
	// returning the proxy here would normally trigger a connection refused error.
	// We return it anyway to demonstrate the actual architecture hooking into the standard library.
	return proxy, nil
}
