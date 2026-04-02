/*
Copyright 2026 Cloudaura sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package threat

import (
	"fmt"
	"regexp"
	"sync"
)

// PatternMatchResult holds a single pattern match result.
type PatternMatchResult struct {
	// SignatureName is the owning signature.
	SignatureName string

	// PatternName is the name of the matched pattern.
	PatternName string

	// Weight is the score weight for this pattern.
	Weight float64
}

// patternEntry holds a compiled regex pattern with its metadata.
type patternEntry struct {
	signatureName string
	patternName   string
	re            *regexp.Regexp
	weight        float64
	target        string
}

// PatternMatcher evaluates regex patterns against content with target filtering.
type PatternMatcher struct {
	mu       sync.RWMutex
	patterns []patternEntry
}

// NewPatternMatcher creates a new empty PatternMatcher.
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{
		patterns: make([]patternEntry, 0),
	}
}

// AddPattern compiles and adds a regex pattern. Returns an error if the regex is invalid.
func (pm *PatternMatcher) AddPattern(signatureName, patternName, regex string, weight float64, target string) error {
	re, err := regexp.Compile(regex)
	if err != nil {
		return fmt.Errorf("invalid regex %q: %w", regex, err)
	}

	pm.mu.Lock()
	pm.patterns = append(pm.patterns, patternEntry{
		signatureName: signatureName,
		patternName:   patternName,
		re:            re,
		weight:        weight,
		target:        target,
	})
	pm.mu.Unlock()

	return nil
}

// RemoveSignature removes all patterns belonging to the given signature.
func (pm *PatternMatcher) RemoveSignature(signatureName string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	filtered := make([]patternEntry, 0, len(pm.patterns))
	for _, p := range pm.patterns {
		if p.signatureName != signatureName {
			filtered = append(filtered, p)
		}
	}
	pm.patterns = filtered
}

// Evaluate runs all patterns against the given content for the specified target.
// Returns a list of matched pattern results.
func (pm *PatternMatcher) Evaluate(target, content string) []PatternMatchResult {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var results []PatternMatchResult

	for _, p := range pm.patterns {
		// Target filtering
		if p.target != "" && p.target != target {
			continue
		}

		if p.re.MatchString(content) {
			results = append(results, PatternMatchResult{
				SignatureName: p.signatureName,
				PatternName:   p.patternName,
				Weight:        p.weight,
			})
		}
	}

	return results
}
