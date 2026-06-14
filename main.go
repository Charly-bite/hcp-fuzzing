package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"stealthfuzzer/client"
)

var (
	targetURLArg = flag.String("url", "", "Target URL to explore (e.g., http://example.com)")
	maxDepthArg  = flag.Int("depth", 1, "Maximum recursion depth")
	wordlistArg  = flag.String("wordlist", "", "Wordlist file (Optional)")
	filtersArg   = flag.String("filters", "200", "Comma-separated list of HTTP status codes to record (e.g. 200,403,401)")
	modesArg     = flag.String("modes", "", "Comma-separated list of advanced fuzzing modes (subdomain,api,parameter,method,header)")
)

// Mock proxy handler for our lab environment
func startMockProxy(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("   [MOCK PROXY %s] Routing %s request to %s", addr, r.Method, r.URL.Host)
		r.RequestURI = ""
		r.Header.Del("Proxy-Connection")

		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	log.Printf("-> Spin up mock proxy on %s", addr)
	http.ListenAndServe(addr, mux)
}

func main() {
	log.Println("Initializing Stealth Web Fuzzing Capabilities...")
	log.Println("-> Running Phases 1-3 (Foundation, Fingerprinting, Distribution)")

	// Start local mock proxies in the background just for the lab
	go startMockProxy("127.0.0.1:8080")
	go startMockProxy("127.0.0.1:8081")
	go startMockProxy("127.0.0.1:8082")
	time.Sleep(500 * time.Millisecond) // Give them a moment to start

	// Create Rate limiter: 2 Requests Per Second, 200ms - 2000ms Jitter (as per Web.json spec)
	rateLimiter := client.NewAdaptiveRateLimiter(2.0, 200*time.Millisecond, 2000*time.Millisecond)

	// Initialize Proxy Manager (Distribution Layer)
	// NOTE: Disabled the local mock proxy list because those tiny HTTP servers
	// don't natively support full TLS HTTPS tunneling (CONNECT verb) yet.
	// You would replace this nil with a proper residential proxy array for a real campaign.
	proxyManager, err := client.NewProxyManager([]string{})
	if err != nil {
		proxyManager = nil // Fallback intentionally to direct connection for HTTPS testing
	}

	// Create Core HTTP Client hooked into our layers
	fuzzer := client.NewFuzzClient(rateLimiter, proxyManager)

	// Fetch CLI arguments
	flag.Parse()

	// Parse filters
	var filters []int
	for _, f := range strings.Split(*filtersArg, ",") {
		var code int
		_, err := fmt.Sscanf(strings.TrimSpace(f), "%d", &code)
		if err == nil {
			filters = append(filters, code)
		}
	}
	if len(filters) == 0 {
		filters = []int{200}
	}

	targetURL := *targetURLArg
	reader := bufio.NewReader(os.Stdin)

	if targetURL == "" {
		fmt.Print("[?] Enter Target URL (e.g. http://example.com): ")
		input, _ := reader.ReadString('\n')
		targetURL = strings.TrimSpace(input)
	}

	if targetURL == "" {
		log.Println("[-] No target URL specified. Exiting.")
		return
	}

	// Ensure the URL has an HTTP/HTTPS scheme to prevent 'unsupported protocol scheme' errors
	// Defaulting to https:// for modern targets to avoid 308 permanent redirects
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	wordlistFile := *wordlistArg
	if wordlistFile == "" {
		fmt.Printf("\n[?] Found the following wordlists in ./wordlists/:\n")
		files, _ := filepath.Glob("./wordlists/*.txt")
		for i, f := range files {
			fmt.Printf("   [%d] %s\n", i+1, f)
		}
		fmt.Print("[?] Enter the name of the wordlist to use (e.g. common.txt), or press enter to skip directory fuzzing: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			wordlistFile = filepath.Join("wordlists", input)
		}
	}

	log.Printf("\nTargeting URL: %s with Max Depth: %d\n", targetURL, *maxDepthArg)
	if wordlistFile != "" {
		log.Printf("Loaded Wordlist: %s\n", wordlistFile)
	}

	// Initialize maps
	visited := make(map[string]bool)
	allLinks := []string{}

	// Phase 5: Directory Fuzzing (Optional if wordlist is provided)
	var words []string
	if wordlistFile != "" {
		words, err = client.ReadWordlist(wordlistFile)
		if err == nil && len(words) > 0 {
			client.FuzzDirectories(fuzzer, targetURL, words, &allLinks, filters)
		} else {
			log.Printf("[-] Could not read wordlist %s: %v", wordlistFile, err)
		}
	}

	// Run recursive crawling + fuzzing engine (This performs Phases 1-4 internally per request)
	log.Println("\n[~] Initiating Evasion Crawler Spidering...")
	client.Crawl(fuzzer, targetURL, *maxDepthArg, 0, visited, &allLinks, filters)

	// Phase 6: Advanced Fuzzing Modes
	modes := strings.Split(*modesArg, ",")
	for _, m := range modes {
		m = strings.TrimSpace(m)
		switch m {
		case "subdomain":
			client.FuzzSubdomains(fuzzer, targetURL, words, &allLinks, filters)
		case "api":
			client.FuzzAPI(fuzzer, targetURL, words, &allLinks, filters)
		case "parameter":
			client.FuzzParameters(fuzzer, targetURL, words, &allLinks, filters)
		case "method":
			client.FuzzMethods(fuzzer, targetURL, filters)
		case "header":
			client.FuzzHeaders(fuzzer, targetURL, filters)
		}
	}

	// Output report logic
	reportFile := "Fuzzing_Report.html"
	client.GenerateReport(allLinks, reportFile)

	log.Printf("\n-> Crawl complete! Extracted %d unique links.", len(allLinks))
	log.Printf("-> Downloadable Report generated at: ./%s\n", reportFile)
}
