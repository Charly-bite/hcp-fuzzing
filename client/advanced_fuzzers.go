package client

import (
	"context"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

const specWordlistDir = "/cluster_data/fuzzer/wordlists"

// FuzzSubdomains attempts to discover virtual hosts by manipulating the Host header.
func FuzzSubdomains(fc *FuzzClient, targetBase string, words []string, allLinks *[]string, validStatuses []int) {
	log.Printf("[~] Starting Advanced Subdomain Fuzzing (VHost) on %s", targetBase)

	// Load specialized subdomain wordlist
	subWords, err := ReadWordlist(filepath.Join(specWordlistDir, "subdomains.txt"))
	if err != nil {
		log.Printf("[-] Error loading subdomain wordlist, falling back to campaign wordlist: %v", err)
		subWords = words
	}

	for _, word := range subWords {
		host := word + "." + targetBase
		// Remove protocol if it's in the host header
		host = strings.ReplaceAll(host, "http://", "")
		host = strings.ReplaceAll(host, "https://", "")

		req, _ := http.NewRequestWithContext(context.Background(), "GET", targetBase, nil)
		req.Host = host
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Subdomain! %s -> %s (Status: %d, Size: %d)", host, targetBase, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] Subdomain Fuzzing Phase Complete.")
}

// FuzzAPI attempts to discover hidden API endpoints by altering Content-Type and appending /api/ paths.
func FuzzAPI(fc *FuzzClient, targetBase string, words []string, allLinks *[]string, validStatuses []int) {
	log.Printf("[~] Starting Advanced API Fuzzing (JSON/REST/GraphQL) on %s", targetBase)

	apiWords, err := ReadWordlist(filepath.Join(specWordlistDir, "api_endpoints.txt"))
	if err != nil {
		log.Printf("[-] Error loading API wordlist, falling back to campaign wordlist: %v", err)
		apiWords = words
	}

	for _, p := range apiWords {
		testURL := strings.TrimRight(targetBase, "/") + "/" + p
		req, _ := http.NewRequestWithContext(context.Background(), "POST", testURL, strings.NewReader(`{"test":true}`))
		req.Header.Set("Content-Type", "application/json")

		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found API! %s (Status: %d, Size: %d)", testURL, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] API Fuzzing Phase Complete.")
}

// FuzzParameters attempts to discover hidden query parameters on discovered endpoints.
func FuzzParameters(fc *FuzzClient, targetBase string, words []string, allLinks *[]string, validStatuses []int) {
	log.Printf("[~] Starting Advanced Parameter Fuzzing on %s", targetBase)

	paramWords, err := ReadWordlist(filepath.Join(specWordlistDir, "parameters.txt"))
	if err != nil {
		log.Printf("[-] Error loading parameter wordlist: %v", err)
		return
	}

	for _, word := range paramWords {
		testURL := targetBase
		if strings.Contains(targetBase, "?") {
			testURL += "&" + word + "=1"
		} else {
			testURL += "?" + word + "=1"
		}

		req, _ := http.NewRequestWithContext(context.Background(), "GET", testURL, nil)
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Parameter! %s (Status: %d, Size: %d)", testURL, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}

	log.Printf("[+] Parameter Fuzzing Phase Complete.")
}

// FuzzMethods cycles through HTTP methods on endpoints.
func FuzzMethods(fc *FuzzClient, targetBase string, validStatuses []int) {
	log.Printf("[~] Starting Advanced HTTP Method Fuzzing on %s", targetBase)

	methodWords, err := ReadWordlist(filepath.Join(specWordlistDir, "http_methods.txt"))
	if err != nil {
		log.Printf("[-] Error loading methods wordlist: %v", err)
		return
	}

	for _, method := range methodWords {
		req, _ := http.NewRequestWithContext(context.Background(), method, targetBase, nil)
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Method! [%s] %s (Status: %d, Size: %d)", method, targetBase, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] HTTP Method Fuzzing Phase Complete.")
}

// FuzzHeaders injects evasion headers to bypass auth or firewalls.
func FuzzHeaders(fc *FuzzClient, targetBase string, validStatuses []int) {
	log.Printf("[~] Starting Advanced Header/Bypass Fuzzing on %s", targetBase)

	headerWords, err := ReadWordlist(filepath.Join(specWordlistDir, "headers_injection.txt"))
	if err != nil {
		log.Printf("[-] Error loading headers wordlist: %v", err)
		return
	}

	for _, key := range headerWords {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", targetBase, nil)
		req.Header.Set(key, "127.0.0.1")
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Header Bypass! [%s: 127.0.0.1] %s (Status: %d, Size: %d)", key, targetBase, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] Header Fuzzing Phase Complete.")
}
