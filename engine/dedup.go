package engine

import (
	"github.com/grepstrength/malsnitch/detector"
)

//package level variable. initialized once
var confidenceRank = map[string]int{
	"high":   3,
	"medium": 2,
	"low":    1,
}

func dedup(findings []detector.Finding) []detector.Finding{
	type key struct { //the key type is only used here
		lineNumber	int
		secret		string
	}

	best := make(map[key]detector.Finding) //this stores the best finding fo each unique key

	for _, f := range findings {
		k := key{lineNumber: f.LineNumber, secret: f.Secret}

		existing, exists := best[k] //returns only two values
		if !exists {
			best[k] = f
			continue
		}
		if confidenceRank[f.Confidence] > confidenceRank[existing.Confidence] { //compare the numeric ranks
			best[k] = f
		}
	}
	var result []detector.Finding
	for _, f := range best {
		result = append(result, f)
	}
	return result
}

//compares every finding against every other inding on the same line
//if A's secret is a shorter substring of B's secret, A gets droped
func removeSubstrings(findings []detector.Finding) []detector.Finding {
	var result []detector.Finding

	for i, f := range findings {
		isSubstring := false

		for j, other := range findings {
			if i == j {
				continue
			}

			if f.LineNumber == other.LineNumber &&
				len(f.Secret) < len(other.Secret) &&
				containsString(other.Secret, f.Secret) {
				isSubstring = true
				break
			}
		}

		if !isSubstring {
			result = append(result, f)
		}
	}

	return result
}

func containsString(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) > len(needle) &&
		indexOf(haystack, needle) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}