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
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Helper to create a policy with a single predicate.
func makePredicatePolicy(name, celExpr string) *v1alpha1.PanoptiumPolicy {
	return &v1alpha1.PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: v1alpha1.PanoptiumPolicySpec{
			TargetSelector:  metav1.LabelSelector{},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []v1alpha1.PolicyRule{
				{
					Name: "test-rule",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "protocol",
						EventSubcategory: "tool_call",
					},
					Predicates: []v1alpha1.Predicate{
						{CEL: celExpr},
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			},
		},
	}
}

// Test: Basic equality -- event.toolName == "bash".
func TestCEL_BasicEquality(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("equality", `event.toolName == "bash"`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// Should match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for toolName==bash")
	}

	// Should not match
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "python"},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for toolName==python")
	}
}

// Test: Inequality -- event.toolName != "safe_tool".
func TestCEL_Inequality(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("inequality", `event.toolName != "safe_tool"`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// "bash" != "safe_tool" => should match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match (bash != safe_tool)")
	}

	// "safe_tool" != "safe_tool" => should NOT match
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "safe_tool"},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match (safe_tool != safe_tool is false)")
	}
}

// Test: Numeric comparison -- event.tokenCount > 1000.
func TestCEL_NumericComparison(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("numeric", `event.tokenCount > 1000`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// 2000 > 1000 => match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"tokenCount": 2000},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match (2000 > 1000)")
	}

	// 500 > 1000 => no match
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"tokenCount": 500},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match (500 > 1000 is false)")
	}
}

// Test: Custom function matches() -- event.processName.matches(".*malicious.*").
func TestCEL_MatchesFunction(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("regex", `event.processName.matches(".*malicious.*")`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// Should match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"processName": "run_malicious_script"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for malicious process name")
	}

	// Should not match
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"processName": "safe_tool"},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for safe_tool")
	}
}

// Test: Custom function glob() -- event.path.glob("/etc/**").
func TestCEL_GlobFunction(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("glob-test", `event.path.glob("/etc/**")`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// Should match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"path": "/etc/passwd"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for /etc/passwd against /etc/**")
	}

	// Should not match
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"path": "/var/log/syslog"},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for /var/log/syslog against /etc/**")
	}
}

// Test: Custom function inCIDR() -- event.sourceIP.inCIDR("10.0.0.0/8").
func TestCEL_InCIDRFunction(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("cidr-test", `event.sourceIP.inCIDR("10.0.0.0/8")`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// Should match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"sourceIP": "10.1.2.3"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for 10.1.2.3 in 10.0.0.0/8")
	}

	// Should not match
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"sourceIP": "192.168.1.1"},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for 192.168.1.1 in 10.0.0.0/8")
	}
}

// Test: Complex expression -- event.toolName == "bash" && event.model == "gpt-4".
func TestCEL_ComplexExpression(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("complex", `event.toolName == "bash" && event.model == "gpt-4"`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	// Both conditions match
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash", "model": "gpt-4"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for bash+gpt-4")
	}

	// Only one condition matches
	event2 := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash", "model": "claude"},
	}
	decision2, err := dt.Evaluate(event2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision2.Matched {
		t.Error("expected no match for bash+claude")
	}
}

// Test: Invalid CEL expression returns CompilationError.
func TestCEL_InvalidExpressionReturnsError(t *testing.T) {
	compiler := NewPolicyCompiler()

	invalidExprs := []string{
		`event.toolName ===`,         // syntax error
		`gibberish not valid CEL`,    // not valid CEL
		`event.unknown_func()`,       // unknown function
	}

	for _, expr := range invalidExprs {
		pol := makePredicatePolicy("invalid", expr)
		_, err := compiler.Compile(pol)
		if err == nil {
			t.Errorf("expected CompilationError for expression %q, got nil", expr)
		} else {
			// Verify it's a CompilationError
			if _, ok := err.(*CompilationError); !ok {
				t.Errorf("expected *CompilationError for expression %q, got %T: %v", expr, err, err)
			}
		}
	}
}

// Test: Single-quoted values -- event.toolName == 'bash'.
func TestCEL_SingleQuotedValues(t *testing.T) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("single-quote", `event.toolName == 'bash'`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)

	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash"},
	}
	decision, err := dt.Evaluate(event)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Matched {
		t.Error("expected match for single-quoted bash")
	}
}

// Benchmark: CEL evaluation should be <1ms per predicate.
func BenchmarkCEL_PredicateEvaluation(b *testing.B) {
	compiler := NewPolicyCompiler()
	pol := makePredicatePolicy("bench", `event.toolName == "bash" && event.model == "gpt-4"`)

	compiled, err := compiler.Compile(pol)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}

	dt := NewDecisionTree(compiled)
	event := &PolicyEvent{
		Category:    "protocol",
		Subcategory: "tool_call",
		Fields:      map[string]interface{}{"toolName": "bash", "model": "gpt-4"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dt.Evaluate(event)
	}

	// Verify that per-evaluation time is < 1ms
	elapsed := b.Elapsed()
	perOp := elapsed / time.Duration(b.N)
	if perOp > 1*time.Millisecond {
		b.Errorf("CEL evaluation took %v per operation, expected <1ms", perOp)
	}
}
