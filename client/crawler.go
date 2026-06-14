package client

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/html"
)

// Crawl recursively visits links up to maxDepth and collects them
func Crawl(fc *FuzzClient, currentURL string, maxDepth int, currentDepth int, visited map[string]bool, allLinks *[]string, validStatuses []int) {
	if currentDepth > maxDepth {
		return
	}

	parsed, err := url.Parse(currentURL)
	if err != nil || visited[currentURL] {
		return
	}
	visited[currentURL] = true

	log.Printf("=> [CRAWL Depth %d] Fetching target: %s", currentDepth, currentURL)

	req, err := http.NewRequestWithContext(context.Background(), "GET", currentURL, nil)
	if err != nil {
		return
	}

	resp, err := fc.Do(req)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	if !containsInt(validStatuses, resp.StatusCode) {
		return
	}

	z := html.NewTokenizer(resp.Body)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			if t.Data == "a" {
				for _, a := range t.Attr {
					if a.Key == "href" {
						link := a.Val
						absLink := resolveURL(parsed, link)
						if absLink != "" && strings.HasPrefix(absLink, "http") {
							if !contains(*allLinks, absLink) {
								*allLinks = append(*allLinks, absLink)
							}
							// Recurse conditionally
							if !visited[absLink] {
								Crawl(fc, absLink, maxDepth, currentDepth+1, visited, allLinks, validStatuses)
							}
						}
						break
					}
				}
			}
		}
	}
}

func resolveURL(base *url.URL, ref string) string {
	if strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

// GenerateReport writes the discovered links into to a clickable HTML file
func GenerateReport(links []string, filename string) {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><title>Fuzzer Execution Report</title>")
	sb.WriteString("<style>body{font-family: Arial;} a{text-decoration:none;color:#0078D7;}</style></head><body>")
	sb.WriteString("<h2>Stealth Fuzzer - Discovered Links</h2><ul>")
	for _, l := range links {
		sb.WriteString(fmt.Sprintf("<li><a href=\"%s\" target=\"_blank\">%s</a></li>", l, l))
	}
	sb.WriteString("</ul></body></html>")

	err := os.WriteFile(filename, []byte(sb.String()), 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to save report: %v", err)
	}
}
