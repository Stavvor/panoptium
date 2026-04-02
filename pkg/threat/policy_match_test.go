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
	"testing"
)

// TestPolicyMatcher_MatchByName verifies policy rule matching by signature name.
func TestPolicyMatcher_MatchByName(t *testing.T) {
	pm := NewPolicyMatcher()

	result := MatchResult{
		SignatureName: "mcp-ignore-instructions",
		Category:      "prompt_injection",
		Severity:      "critical",
		Score:         0.9,
	}

	match := ThreatSignatureSelector{
		Names: []string{"mcp-ignore-instructions", "mcp-role-confusion"},
	}

	if !pm.Matches(result, match) {
		t.Error("PolicyMatcher.Matches() = false, want true for matching name")
	}
}

// TestPolicyMatcher_MatchByNameNoMatch verifies no match when name is not in list.
func TestPolicyMatcher_MatchByNameNoMatch(t *testing.T) {
	pm := NewPolicyMatcher()

	result := MatchResult{
		SignatureName: "mcp-other",
		Category:      "prompt_injection",
		Severity:      "critical",
	}

	match := ThreatSignatureSelector{
		Names: []string{"mcp-ignore-instructions"},
	}

	if pm.Matches(result, match) {
		t.Error("PolicyMatcher.Matches() = true, want false for non-matching name")
	}
}

// TestPolicyMatcher_MatchByCategory verifies matching by category selector.
func TestPolicyMatcher_MatchByCategory(t *testing.T) {
	pm := NewPolicyMatcher()

	result := MatchResult{
		SignatureName: "some-sig",
		Category:      "prompt_injection",
		Severity:      "high",
	}

	match := ThreatSignatureSelector{
		Categories: []string{"prompt_injection", "data_exfiltration"},
	}

	if !pm.Matches(result, match) {
		t.Error("PolicyMatcher.Matches() = false, want true for matching category")
	}
}

// TestPolicyMatcher_MatchBySeverity verifies matching by severity selector.
func TestPolicyMatcher_MatchBySeverity(t *testing.T) {
	pm := NewPolicyMatcher()

	result := MatchResult{
		SignatureName: "some-sig",
		Category:      "prompt_injection",
		Severity:      "critical",
	}

	match := ThreatSignatureSelector{
		Severities: []string{"critical", "high"},
	}

	if !pm.Matches(result, match) {
		t.Error("PolicyMatcher.Matches() = false, want true for matching severity")
	}
}

// TestPolicyMatcher_MatchBySeverityNoMatch verifies no match for wrong severity.
func TestPolicyMatcher_MatchBySeverityNoMatch(t *testing.T) {
	pm := NewPolicyMatcher()

	result := MatchResult{
		SignatureName: "some-sig",
		Category:      "prompt_injection",
		Severity:      "low",
	}

	match := ThreatSignatureSelector{
		Severities: []string{"critical", "high"},
	}

	if pm.Matches(result, match) {
		t.Error("PolicyMatcher.Matches() = true, want false for non-matching severity")
	}
}

// TestPolicyMatcher_EmptySelector verifies empty selector matches nothing.
func TestPolicyMatcher_EmptySelector(t *testing.T) {
	pm := NewPolicyMatcher()

	result := MatchResult{
		SignatureName: "some-sig",
		Category:      "prompt_injection",
		Severity:      "critical",
	}

	match := ThreatSignatureSelector{} // empty

	if pm.Matches(result, match) {
		t.Error("PolicyMatcher.Matches() = true, want false for empty selector")
	}
}

// TestPolicyMatcher_CombinedSelector verifies matching with combined name+category+severity.
func TestPolicyMatcher_CombinedSelector(t *testing.T) {
	pm := NewPolicyMatcher()

	result := MatchResult{
		SignatureName: "mcp-injection",
		Category:      "prompt_injection",
		Severity:      "critical",
	}

	// All criteria must match when specified
	match := ThreatSignatureSelector{
		Names:      []string{"mcp-injection"},
		Categories: []string{"prompt_injection"},
		Severities: []string{"critical"},
	}

	if !pm.Matches(result, match) {
		t.Error("PolicyMatcher.Matches() = false, want true for combined match")
	}

	// Partial mismatch should fail
	matchFail := ThreatSignatureSelector{
		Names:      []string{"mcp-injection"},
		Categories: []string{"data_exfiltration"}, // wrong category
		Severities: []string{"critical"},
	}

	if pm.Matches(result, matchFail) {
		t.Error("PolicyMatcher.Matches() = true, want false for partial mismatch")
	}
}
