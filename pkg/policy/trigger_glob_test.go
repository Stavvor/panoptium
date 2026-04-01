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

package policy

import (
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// Test: Trigger with EventSubcategory="tool_*" matches event with Subcategory="tool_call".
func TestTriggerGlob_WildcardSuffix(t *testing.T) {
	compiled := &CompiledPolicy{
		Name: "trigger-glob-test",
		Rules: []*CompiledRule{
			{
				Name:         "glob-trigger",
				TriggerLayer: "protocol",
				TriggerEvent: "tool_*",
				Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
			},
		},
	}

	dt := NewDecisionTree(compiled)

	// tool_call matches tool_*
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match: tool_call should match trigger tool_*")
	}

	// tool_response matches tool_*
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_response",
		Fields:      map[string]interface{}{},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision2.Matched {
		t.Error("expected match: tool_response should match trigger tool_*")
	}

	// message_send does NOT match tool_*
	event3 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "message_send",
		Fields:      map[string]interface{}{},
	}
	decision3, err := dt.Evaluate(event3)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision3.Matched {
		t.Error("expected no match: message_send should not match trigger tool_*")
	}
}

// Test: Trigger with EventSubcategory="*" matches any subcategory.
func TestTriggerGlob_MatchAll(t *testing.T) {
	compiled := &CompiledPolicy{
		Name: "trigger-glob-all",
		Rules: []*CompiledRule{
			{
				Name:         "match-all-trigger",
				TriggerLayer: "protocol",
				TriggerEvent: "*",
				Action:       CompiledAction{Type: v1alpha1.ActionTypeAlert},
			},
		},
	}

	dt := NewDecisionTree(compiled)

	subcategories := []string{"tool_call", "tool_response", "message_send", "llm_request"}
	for _, sub := range subcategories {
		event := &PolicyEvent{
			Category:    "protocol",
			Subcategory: sub,
			Fields:      map[string]interface{}{},
		}
		decision, err := dt.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluate(%s): %v", sub, err)
		}
		if !decision.Matched {
			t.Errorf("expected match for subcategory %q against trigger '*'", sub)
		}
	}
}

// Test: Exact match still works when no glob characters are present.
func TestTriggerGlob_ExactMatchPreserved(t *testing.T) {
	compiled := &CompiledPolicy{
		Name: "trigger-exact",
		Rules: []*CompiledRule{
			{
				Name:         "exact-trigger",
				TriggerLayer: "kernel",
				TriggerEvent: "process_exec",
				Action:       CompiledAction{Type: v1alpha1.ActionTypeDeny},
			},
		},
	}

	dt := NewDecisionTree(compiled)

	// Exact match
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for exact trigger match")
	}

	// Non-match
	event2 := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "file_open",
		Fields:      map[string]interface{}{},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for different subcategory")
	}
}
