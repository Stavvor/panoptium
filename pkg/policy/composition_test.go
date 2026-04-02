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
	"net"
	"regexp"
	"testing"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPolicyComposition_DescendingPriorityOrdering(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "low-priority",
			Namespace: "default",
			Priority:  10,
			Rules: []*CompiledRule{
				{
					Name:         "low-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "allow"},
				},
			},
		},
		{
			Name:      "high-priority",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "high-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != "deny" {
		t.Errorf("expected deny (from high-priority policy), got %q", decision.Action.Type)
	}
	if decision.PolicyName != "high-priority" {
		t.Errorf("expected PolicyName=high-priority, got %q", decision.PolicyName)
	}
}

func TestPolicyComposition_FirstMatchWithinPolicy(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "test-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "first-rule",
					Index:        0,
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.processName", Operator: "==", Value: "curl"},
					},
				},
				{
					Name:         "second-rule",
					Index:        1,
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "allow"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.MatchedRule != "first-rule" {
		t.Errorf("expected first-rule (first match), got %q", decision.MatchedRule)
	}
	if decision.Action.Type != "deny" {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_NamespaceOverridesCluster(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "cluster-policy",
			Namespace:       "",
			Priority:        100,
			IsClusterScoped: true,
			Rules: []*CompiledRule{
				{
					Name:         "cluster-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
		{
			Name:            "namespace-policy",
			Namespace:       "default",
			Priority:        100, // same priority
			IsClusterScoped: false,
			Rules: []*CompiledRule{
				{
					Name:         "namespace-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "allow"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected allow (namespace overrides cluster at equal priority), got %q", decision.Action.Type)
	}
	if decision.PolicyName != "namespace-policy" {
		t.Errorf("expected namespace-policy, got %q", decision.PolicyName)
	}
}

func TestPolicyComposition_ExplicitAllowOverridesDeny(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "deny-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
		{
			Name:      "allow-policy",
			Namespace: "default",
			Priority:  100, // same priority
			Rules: []*CompiledRule{
				{
					Name:         "allow-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "allow"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected allow (explicit allow overrides deny at equal priority), got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_DeterministicEvaluation(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "policy-a",
			Namespace: "default",
			Priority:  50,
			Rules: []*CompiledRule{
				{
					Name:         "rule-a",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
		{
			Name:      "policy-b",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "rule-b",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	// Evaluate multiple times and verify same result
	for i := 0; i < 10; i++ {
		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if decision.Action.Type != "deny" {
			t.Errorf("iteration %d: expected deny, got %q", i, decision.Action.Type)
		}
		if decision.PolicyName != "policy-b" {
			t.Errorf("iteration %d: expected policy-b, got %q", i, decision.PolicyName)
		}
	}
}

func TestPolicyComposition_NoMatchDefaultAllow(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "network-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "network-rule",
					TriggerLayer: "network",
					TriggerEvent: "egress_attempt",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match (no kernel rule), got match")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_EmptyPolicySet(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Fields:      map[string]interface{}{},
	}

	decision, err := resolver.Evaluate([]*CompiledPolicy{}, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match with empty policy set")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_PredicateEvaluation(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "test-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "regex-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.processName", Operator: "matches", Value: "^curl.*"},
					},
					CompiledRegexes: map[string]*regexp.Regexp{
						"^curl.*": regexp.MustCompile("^curl.*"),
					},
					CompiledGlobs: map[string]*GlobMatcher{},
					CompiledCIDRs: map[string]*net.IPNet{},
				},
			},
		},
	}

	// Matching event
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match on regex predicate")
	}

	// Non-matching event
	event2 := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "python"},
	}

	decision2, err := resolver.Evaluate(policies, event2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for python (regex ^curl.* doesn't match)")
	}
}

func TestPolicyComposition_TiebreakByPolicyName(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	// Two namespace-scoped policies with same priority
	policies := []*CompiledPolicy{
		{
			Name:      "zzz-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "zzz-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
		{
			Name:      "aaa-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "aaa-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: v1alpha1.ActionType("alert")},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "default",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With same priority and both namespace-scoped, aaa-policy sorts first by name
	if decision.PolicyName != "aaa-policy" {
		t.Errorf("expected aaa-policy (alphabetical tiebreak), got %q", decision.PolicyName)
	}
}

// mockRateLimitCounter implements RateLimitCounter for testing.
type mockRateLimitCounter struct {
	count int
}

func (m *mockRateLimitCounter) IncrementAndCheck(key string, limit int) bool {
	m.count++
	return m.count > limit
}

func TestPolicyComposition_RateLimitWithinBurst(t *testing.T) {
	counter := &mockRateLimitCounter{}
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "rate-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "throttle-rule",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: "rateLimit",
						Parameters: map[string]string{
							"burstSize":         "3",
							"requestsPerMinute": "3",
						},
					},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.toolName", Operator: "==", Value: "rate_test"},
					},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "rate_test"},
	}

	// First 3 requests should be allowed (within burst of 3)
	for i := 1; i <= 3; i++ {
		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if decision.Matched {
			t.Errorf("request %d: expected no match (under rate limit), got matched with action %q", i, decision.Action.Type)
		}
		if decision.Action.Type != "allow" {
			t.Errorf("request %d: expected allow action, got %q", i, decision.Action.Type)
		}
	}

	// 4th request should be rate limited
	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("4th request: unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("4th request: expected match (rate limit exceeded)")
	}
	if decision.Action.Type != "rateLimit" {
		t.Errorf("4th request: expected rateLimit action, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_RateLimitWithoutCounter(t *testing.T) {
	// Without a counter, rateLimit decisions should be returned as-is
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:      "rate-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "throttle-rule",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: "rateLimit",
						Parameters: map[string]string{
							"burstSize":         "3",
							"requestsPerMinute": "3",
						},
					},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.toolName", Operator: "==", Value: "rate_test"},
					},
				},
			},
		},
	}

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "rate_test"},
	}

	// Without counter, should always return matched rateLimit
	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match (no counter = rateLimit returned as-is)")
	}
	if decision.Action.Type != "rateLimit" {
		t.Errorf("expected rateLimit action, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_RateLimitNonMatchingEvent(t *testing.T) {
	counter := &mockRateLimitCounter{}
	resolver := NewPolicyCompositionResolverWithRateLimit(counter)

	policies := []*CompiledPolicy{
		{
			Name:      "rate-policy",
			Namespace: "default",
			Priority:  100,
			Rules: []*CompiledRule{
				{
					Name:         "throttle-rule",
					TriggerLayer: "protocol",
					TriggerEvent: "tool_call",
					Action: CompiledAction{
						Type: "rateLimit",
						Parameters: map[string]string{
							"burstSize":         "3",
							"requestsPerMinute": "3",
						},
					},
					Predicates: []CompiledPredicate{
						{FieldPath: "event.toolName", Operator: "==", Value: "rate_test"},
					},
				},
			},
		},
	}

	// Event with different tool name should not match at all
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Namespace:   "default",
		Fields:      map[string]interface{}{"toolName": "other_tool"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("expected no match for non-matching event")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
	// Counter should not have been touched
	if counter.count != 0 {
		t.Errorf("expected counter.count=0 (no rate limit check), got %d", counter.count)
	}
}

// --- Namespace scoping tests ---

func TestPolicyComposition_NamespacedPolicy_DoesNotMatchPodInOtherNamespace(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "foo-policy",
			Namespace:       "foo",
			Priority:        100,
			IsClusterScoped: false,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	// Event is from namespace "bar" — policy in "foo" should NOT match
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "bar",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("namespaced policy in 'foo' should NOT match pod in namespace 'bar'")
	}
	if decision.Action.Type != "allow" {
		t.Errorf("expected default allow, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_NamespacedPolicy_MatchesPodInSameNamespace(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "foo-policy",
			Namespace:       "foo",
			Priority:        100,
			IsClusterScoped: false,
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	// Event is from the same namespace "foo" — should match
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "foo",
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("namespaced policy should match pod in same namespace")
	}
	if decision.Action.Type != "deny" {
		t.Errorf("expected deny, got %q", decision.Action.Type)
	}
}

func TestPolicyComposition_NamespacedPolicy_EmptyTargetSelector_MatchesAllPodsInNamespace(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "wildcard-ns-policy",
			Namespace:       "production",
			Priority:        100,
			IsClusterScoped: false,
			TargetSelector:  nil, // empty selector = all pods
			Rules: []*CompiledRule{
				{
					Name:         "alert-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
	}

	// Pod in same namespace — should match
	eventSame := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "production",
		PodLabels:   map[string]string{"app": "anything"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, eventSame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Matched {
		t.Error("empty targetSelector + same namespace should match")
	}

	// Pod in different namespace — should NOT match
	eventOther := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "staging",
		PodLabels:   map[string]string{"app": "anything"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision2, err := resolver.Evaluate(policies, eventOther)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision2.Matched {
		t.Error("empty targetSelector on namespaced policy should NOT match pods in other namespace")
	}
}

func TestPolicyComposition_ClusterPolicy_EmptyTargetSelector_MatchesAllPods(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "global-policy",
			Namespace:       "",
			Priority:        100,
			IsClusterScoped: true,
			TargetSelector:  nil, // empty selector = all pods
			Rules: []*CompiledRule{
				{
					Name:         "alert-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "alert"},
				},
			},
		},
	}

	// Should match pods in any namespace
	for _, ns := range []string{"production", "staging", "default", ""} {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Namespace:   ns,
			Fields:      map[string]interface{}{"processName": "curl"},
		}

		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("unexpected error for ns %q: %v", ns, err)
		}
		if !decision.Matched {
			t.Errorf("cluster policy with empty targetSelector should match pod in namespace %q", ns)
		}
	}
}

func TestPolicyComposition_ClusterPolicy_WithSelector_MatchesAcrossNamespaces(t *testing.T) {
	resolver := NewPolicyCompositionResolver()

	policies := []*CompiledPolicy{
		{
			Name:            "global-labeled-policy",
			Namespace:       "",
			Priority:        100,
			IsClusterScoped: true,
			TargetSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "agents"},
			},
			Rules: []*CompiledRule{
				{
					Name:         "deny-rule",
					TriggerLayer: "kernel",
					TriggerEvent: "process_exec",
					Action:       CompiledAction{Type: "deny"},
				},
			},
		},
	}

	// Matching labels in different namespaces — cluster policy matches all
	for _, ns := range []string{"ns-a", "ns-b", "ns-c"} {
		event := &PolicyEvent{
			Category:    "kernel",
			Subcategory: "process_exec",
			Namespace:   ns,
			PodLabels:   map[string]string{"tier": "agents"},
			Fields:      map[string]interface{}{"processName": "curl"},
		}

		decision, err := resolver.Evaluate(policies, event)
		if err != nil {
			t.Fatalf("unexpected error for ns %q: %v", ns, err)
		}
		if !decision.Matched {
			t.Errorf("cluster policy should match label-matching pod in namespace %q", ns)
		}
	}

	// Non-matching labels — should NOT match
	event := &PolicyEvent{
		Category:    "kernel",
		Subcategory: "process_exec",
		Namespace:   "ns-a",
		PodLabels:   map[string]string{"tier": "web"},
		Fields:      map[string]interface{}{"processName": "curl"},
	}

	decision, err := resolver.Evaluate(policies, event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Matched {
		t.Error("cluster policy should NOT match pod without matching labels")
	}
}
