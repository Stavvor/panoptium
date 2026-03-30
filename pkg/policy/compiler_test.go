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

// --- Test Helpers ---

// newTestPolicy creates a PanoptiumPolicy with the given rules for testing.
func newTestPolicy(name, namespace string, priority int32, rules []v1alpha1.PolicyRule) *v1alpha1.PanoptiumPolicy {
	return &v1alpha1.PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			EnforcementMode: v1alpha1.EnforcementModeEnforcing,
			Priority:        priority,
			Rules:           rules,
		},
	}
}

// --- Compiler Tests ---

func TestPolicyCompiler_ValidPolicy(t *testing.T) {
	policy := newTestPolicy("test-policy", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "deny-curl",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName == "curl"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if compiled == nil {
		t.Fatal("Compile() returned nil CompiledPolicy")
	}
	if compiled.Name != "test-policy" {
		t.Errorf("CompiledPolicy.Name = %q, want %q", compiled.Name, "test-policy")
	}
	if compiled.Namespace != "default" {
		t.Errorf("CompiledPolicy.Namespace = %q, want %q", compiled.Namespace, "default")
	}
	if compiled.Priority != 100 {
		t.Errorf("CompiledPolicy.Priority = %d, want %d", compiled.Priority, 100)
	}
	if len(compiled.Rules) != 1 {
		t.Fatalf("CompiledPolicy.Rules length = %d, want 1", len(compiled.Rules))
	}
}

func TestPolicyCompiler_TriggerParsing_KernelLayer(t *testing.T) {
	kernelEvents := []string{
		"file_open", "file_write", "file_delete",
		"process_exec", "process_fork", "module_load", "capability_use",
	}
	for _, evt := range kernelEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("kernel-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for kernel/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "kernel" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "kernel")
			}
			if compiled.Rules[0].TriggerEvent != evt {
				t.Errorf("TriggerEvent = %q, want %q", compiled.Rules[0].TriggerEvent, evt)
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_NetworkLayer(t *testing.T) {
	networkEvents := []string{
		"egress_attempt", "ingress_attempt", "dns_query",
		"dns_response", "connection_established", "connection_closed",
	}
	for _, evt := range networkEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("network-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "network",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for network/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "network" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "network")
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_ProtocolLayer(t *testing.T) {
	protocolEvents := []string{
		"tool_call", "tool_response", "message_send", "message_receive", "task_delegate",
	}
	for _, evt := range protocolEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("protocol-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "protocol",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for protocol/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "protocol" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "protocol")
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_LLMLayer(t *testing.T) {
	llmEvents := []string{
		"prompt_submit", "completion_receive", "tool_use_intent", "function_call", "token_stream",
	}
	for _, evt := range llmEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("llm-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "llm",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for llm/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "llm" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "llm")
			}
		})
	}
}

func TestPolicyCompiler_TriggerParsing_LifecycleLayer(t *testing.T) {
	lifecycleEvents := []string{
		"pod_start", "pod_stop", "container_exec", "agent_register", "agent_deregister",
	}
	for _, evt := range lifecycleEvents {
		t.Run(evt, func(t *testing.T) {
			policy := newTestPolicy("lifecycle-"+evt, "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-" + evt,
					Trigger: v1alpha1.Trigger{
						EventCategory:    "lifecycle",
						EventSubcategory: evt,
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
					Severity: v1alpha1.SeverityMedium,
				},
			})
			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() error for lifecycle/%s: %v", evt, err)
			}
			if compiled.Rules[0].TriggerLayer != "lifecycle" {
				t.Errorf("TriggerLayer = %q, want %q", compiled.Rules[0].TriggerLayer, "lifecycle")
			}
		})
	}
}

func TestPolicyCompiler_PrecompiledRegex(t *testing.T) {
	policy := newTestPolicy("regex-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "regex-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName.matches("^(curl|wget)$")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules[0].CompiledRegexes) == 0 {
		t.Error("expected pre-compiled regex matchers, got none")
	}
}

func TestPolicyCompiler_PrecompiledGlob(t *testing.T) {
	policy := newTestPolicy("glob-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "glob-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "file_open",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.path.glob("/etc/**")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules[0].CompiledGlobs) == 0 {
		t.Error("expected pre-compiled glob matchers, got none")
	}
}

func TestPolicyCompiler_PrecompiledCIDR(t *testing.T) {
	policy := newTestPolicy("cidr-test", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "cidr-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "network",
				EventSubcategory: "egress_attempt",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.destinationIP.inCIDR("10.0.0.0/8")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules[0].CompiledCIDRs) == 0 {
		t.Error("expected pre-compiled CIDR matchers, got none")
	}
}

func TestPolicyCompiler_InvalidRegex(t *testing.T) {
	policy := newTestPolicy("bad-regex", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-regex-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName.matches("[invalid")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() expected error for invalid regex, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestPolicyCompiler_UnknownTriggerType(t *testing.T) {
	policy := newTestPolicy("unknown-trigger", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-trigger-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "nonexistent",
				EventSubcategory: "something",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() expected error for unknown trigger type, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestPolicyCompiler_MalformedCIDR(t *testing.T) {
	policy := newTestPolicy("bad-cidr", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "bad-cidr-rule",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "network",
				EventSubcategory: "egress_attempt",
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.destinationIP.inCIDR("not-a-cidr")`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
	})

	compiler := NewPolicyCompiler()
	_, err := compiler.Compile(policy)
	if err == nil {
		t.Fatal("Compile() expected error for malformed CIDR, got nil")
	}
	var compErr *CompilationError
	if !asCompilationError(err, &compErr) {
		t.Errorf("expected CompilationError, got %T: %v", err, err)
	}
}

func TestPolicyCompiler_LatencyUnder100ms(t *testing.T) {
	// Create a realistic-sized policy with 50 rules across various triggers.
	rules := make([]v1alpha1.PolicyRule, 50)
	layers := []string{"kernel", "network", "protocol", "llm", "lifecycle"}
	events := map[string][]string{
		"kernel":    {"file_open", "file_write", "process_exec"},
		"network":   {"egress_attempt", "dns_query", "connection_established"},
		"protocol":  {"tool_call", "message_send"},
		"llm":       {"prompt_submit", "completion_receive"},
		"lifecycle": {"pod_start", "container_exec"},
	}

	for i := range rules {
		layer := layers[i%len(layers)]
		evts := events[layer]
		evt := evts[i%len(evts)]
		rules[i] = v1alpha1.PolicyRule{
			Name: "rule-" + layer + "-" + evt,
			Trigger: v1alpha1.Trigger{
				EventCategory:    layer,
				EventSubcategory: evt,
			},
			Predicates: []v1alpha1.Predicate{
				{CEL: `event.processName == "test"`},
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityMedium,
		}
	}

	policy := newTestPolicy("latency-test", "default", 100, rules)
	compiler := NewPolicyCompiler()

	start := time.Now()
	_, err := compiler.Compile(policy)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Compile() took %v, want <100ms", elapsed)
	}
}

func TestPolicyCompiler_MultipleRules(t *testing.T) {
	policy := newTestPolicy("multi-rule", "default", 100, []v1alpha1.PolicyRule{
		{
			Name: "rule-1",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "kernel",
				EventSubcategory: "process_exec",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
			Severity: v1alpha1.SeverityHigh,
		},
		{
			Name: "rule-2",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "network",
				EventSubcategory: "egress_attempt",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAlert},
			Severity: v1alpha1.SeverityMedium,
		},
		{
			Name: "rule-3",
			Trigger: v1alpha1.Trigger{
				EventCategory:    "llm",
				EventSubcategory: "prompt_submit",
			},
			Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeAllow},
			Severity: v1alpha1.SeverityLow,
		},
	})

	compiler := NewPolicyCompiler()
	compiled, err := compiler.Compile(policy)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	if len(compiled.Rules) != 3 {
		t.Errorf("CompiledPolicy.Rules length = %d, want 3", len(compiled.Rules))
	}
}

func TestPolicyCompiler_EnforcementMode(t *testing.T) {
	modes := []v1alpha1.EnforcementMode{
		v1alpha1.EnforcementModeEnforcing,
		v1alpha1.EnforcementModeAudit,
		v1alpha1.EnforcementModeDisabled,
	}
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			policy := newTestPolicy("mode-test", "default", 100, []v1alpha1.PolicyRule{
				{
					Name: "rule-1",
					Trigger: v1alpha1.Trigger{
						EventCategory:    "kernel",
						EventSubcategory: "process_exec",
					},
					Action:   v1alpha1.Action{Type: v1alpha1.ActionTypeDeny},
					Severity: v1alpha1.SeverityHigh,
				},
			})
			policy.Spec.EnforcementMode = mode

			compiler := NewPolicyCompiler()
			compiled, err := compiler.Compile(policy)
			if err != nil {
				t.Fatalf("Compile() unexpected error: %v", err)
			}
			if compiled.EnforcementMode != mode {
				t.Errorf("EnforcementMode = %q, want %q", compiled.EnforcementMode, mode)
			}
		})
	}
}

// asCompilationError is a helper that checks if err is a *CompilationError.
func asCompilationError(err error, target **CompilationError) bool {
	if err == nil {
		return false
	}
	if ce, ok := err.(*CompilationError); ok {
		*target = ce
		return true
	}
	return false
}
