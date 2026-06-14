package client

import (
	"math/rand"
	"net/url"
	"strings"
)

// RandomizeQueryParams takes a base URL and a map of query parameters,
// then shuffles their order to evade WAFs using static regex pattern matching.
func RandomizeQueryParams(baseURL string, params map[string]string) string {
	if len(params) == 0 {
		return baseURL
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}

	// Shuffle the order of the parameters randomly for every request
	rand.Shuffle(len(keys), func(i, j int) {
		keys[i], keys[j] = keys[j], keys[i]
	})

	var queryParts []string
	for _, k := range keys {
		queryParts = append(queryParts, url.QueryEscape(k)+"="+url.QueryEscape(params[k]))
	}

	queryStr := strings.Join(queryParts, "&")

	// Check if base URL already has parameters
	if strings.Contains(baseURL, "?") {
		if strings.HasSuffix(baseURL, "?") || strings.HasSuffix(baseURL, "&") {
			return baseURL + queryStr
		}
		return baseURL + "&" + queryStr
	}
	return baseURL + "?" + queryStr
}
