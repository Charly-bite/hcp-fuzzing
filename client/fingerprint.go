package client

import (
	"math/rand"
	"net/http"
)

// BrowserProfile represents a cohesive set of headers for a specific browser version.
// Keeping them bundled ensures our fingerprint doesn't look like a Frankenstein browser.
type BrowserProfile struct {
	UserAgent       string
	Accept          string
	AcceptLanguage  string
	AcceptEncoding  string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
}

// A small sample pool for Phase 2. Real implementations would load 10,000+ from a DB or file.
var browserProfiles = []BrowserProfile{
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		AcceptLanguage:  "en-US,en;q=0.9",
		AcceptEncoding:  "gzip, deflate, br",
		SecChUa:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage:  "en-US,en;q=0.9",
		AcceptEncoding:  "gzip, deflate, br",
		SecChUa:         "", // Safari doesn't typically send Sec-CH-UA
		SecChUaMobile:   "",
		SecChUaPlatform: "",
	},
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:  "en-US,en;q=0.5",
		AcceptEncoding:  "gzip, deflate, br",
		SecChUa:         "", // Firefox handles sec-ch-ua differently or not at all depending on config
		SecChUaMobile:   "",
		SecChUaPlatform: "",
	},
}

// ApplyRandomFingerprint injects a coherent set of browser headers into the request
func ApplyRandomFingerprint(req *http.Request) {
	profile := browserProfiles[rand.Intn(len(browserProfiles))]

	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", profile.Accept)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	req.Header.Set("Accept-Encoding", profile.AcceptEncoding)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Add Sec-Ch-Ua headers if they exist in the profile (typically Chromium-based browsers)
	if profile.SecChUa != "" {
		req.Header.Set("Sec-Ch-Ua", profile.SecChUa)
		req.Header.Set("Sec-Ch-Ua-Mobile", profile.SecChUaMobile)
		req.Header.Set("Sec-Ch-Ua-Platform", profile.SecChUaPlatform)
	}
}
