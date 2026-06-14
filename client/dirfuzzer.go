package client

import (
	"bufio"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// ReadWordlist reads a file line by line and returns the slice of words

func ReadWordlist(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

func getSoft404Baseline(fc *FuzzClient, base string) (bool, int, int) {
	testURL := base + "/this_path_should_definitely_not_exist_12345"
	req, err := http.NewRequestWithContext(context.Background(), "GET", testURL, nil)
	if err != nil {
		return false, 0, 0
	}

	resp, err := fc.Do(req)
	if err != nil || resp == nil {
		return false, 0, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		strBody := string(bodyBytes)
		words := len(strings.Fields(strBody))
		return true, len(bodyBytes), words
	}
	return false, 0, 0
}

// FuzzDirectories tests the target URL with paths from the wordlist
// and adds successful findings (200 OK) to the allLinks map
func FuzzDirectories(fc *FuzzClient, targetBase string, words []string, allLinks *[]string, validStatuses []int) {
	base := strings.TrimRight(targetBase, "/")

	// Auto-calibrate for Soft 404s
	isSoft404, baselineBytes, baselineWords := getSoft404Baseline(fc, base)
	if isSoft404 {
		log.Printf("[!] Soft 404 detected on target. Calibrating filter: ~%d Bytes, ~%d Words", baselineBytes, baselineWords)
	}

	log.Printf("[~] Starting Directory Fuzzing on %s with %d words...", base, len(words))

	for _, word := range words {
		// Append the payload string
		testURL := base + "/" + word

		req, err := http.NewRequestWithContext(context.Background(), "GET", testURL, nil)
		if err != nil {
			continue
		}

		resp, err := fc.Do(req)
		if err != nil || resp == nil {
			continue
		}

		// If page exists, record it
		if containsInt(validStatuses, resp.StatusCode) {
			bodyBytes, _ := io.ReadAll(resp.Body)
			currentBytes := len(bodyBytes)
			currentWords := len(strings.Fields(string(bodyBytes)))

			isFalsePositive := false
			if isSoft404 && resp.StatusCode == 200 {
				wordDiff := currentWords - baselineWords
				if wordDiff < 0 {
					wordDiff = -wordDiff
				}

				margin := float64(baselineWords) * 0.05
				if margin < 5 {
					margin = 5
				}

				byteDiff := currentBytes - baselineBytes
				if byteDiff < 0 {
					byteDiff = -byteDiff
				}

				// Some sites reflect the injected URL path in the 404 page body.
				// This heavily alters the byte size if the paylaods differ in length by a lot.
				// By using a 15% byte margin and word counts, we account for those dynamic Reflections.
				byteMargin := float64(baselineBytes) * 0.15
				if byteMargin < 50 {
					byteMargin = 50
				}

				// Identify as soft 404 if content length and word count are within margins
				if float64(wordDiff) <= margin && float64(byteDiff) <= byteMargin {
					isFalsePositive = true
				}
			}

			if !isFalsePositive {
				log.Printf("[+] Found Directory! %s (Status: %d, Size: %d, Words: %d)", testURL, resp.StatusCode, currentBytes, currentWords)
				if !contains(*allLinks, testURL) {
					*allLinks = append(*allLinks, testURL)
				}
			}
		}
		resp.Body.Close()
	}
}
