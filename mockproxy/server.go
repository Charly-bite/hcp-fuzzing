package main

import (
	"io"
	"log"
	"net/http"
)

// forwardProxyHandler returns an HTTP handler that forwards requests
// and logs which proxy port intercepted the traffic.
func forwardProxyHandler(port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[Proxy %s] Intercepted %s request to %s", port, r.Method, r.URL.String())

		// In Go's http.Client, RequestURI must be empty when forwarding
		r.RequestURI = ""

		// Remove hop-by-hop headers
		r.Header.Del("Proxy-Connection")

		// Execute the request to the real destination
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			http.Error(w, "Proxy Error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers back to our fuzzer
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		// Copy status code and body
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func startProxy(port string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", forwardProxyHandler(port))
	log.Printf("-> Started Mock Proxy on %s", port)
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("Proxy %s failed: %v", port, err)
	}
}

func main() {
	log.Println("Starting Mock Proxy Fleet for Phase 3...")

	// Start 3 independent local proxies
	go startProxy(":8080") // US-EAST
	go startProxy(":8081") // EU-WEST
	go startProxy(":8082") // AP-SOUTH

	// Block forever so the proxies stay alive
	select {}
}
