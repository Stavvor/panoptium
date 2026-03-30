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

package webhook

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// TestValidateCreate_ValidPolicy verifies that a valid policy passes validation.
func TestValidateCreate_ValidPolicy(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-policy",
			Namespace: "default",
		},
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			EnforcementMode: panoptiumiov1alpha1.EnforcementModeEnforcing,
			Priority:        100,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name: "block-exec",
					Trigger: panoptiumiov1alpha1.Trigger{
						EventCategory: "syscall",
					},
					Action: panoptiumiov1alpha1.Action{
						Type: panoptiumiov1alpha1.ActionTypeDeny,
					},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	warnings, err := v.ValidateCreate(context.Background(), policy)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() warnings = %v, want none", warnings)
	}
}

// TestValidateCreate_PriorityTooHigh verifies rejection of priority > 1000.
func TestValidateCreate_PriorityTooHigh(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Priority: 1001,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:    "r",
					Trigger: panoptiumiov1alpha1.Trigger{EventCategory: "s"},
					Action:  panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Error("ValidateCreate() error = nil, want rejection for priority > 1000")
	}
}

// TestValidateCreate_PriorityTooLow verifies rejection of priority < 1.
func TestValidateCreate_PriorityTooLow(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Priority: 0,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:     "r",
					Trigger:  panoptiumiov1alpha1.Trigger{EventCategory: "s"},
					Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Error("ValidateCreate() error = nil, want rejection for priority < 1")
	}
}

// TestValidateCreate_InvalidCEL verifies rejection of invalid CEL expression.
func TestValidateCreate_InvalidCEL(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Priority: 100,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:    "bad-cel",
					Trigger: panoptiumiov1alpha1.Trigger{EventCategory: "syscall"},
					Predicates: []panoptiumiov1alpha1.Predicate{
						{CEL: "this is not valid CEL !!!{{{"},
					},
					Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Error("ValidateCreate() error = nil, want rejection for invalid CEL expression")
	}
}

// TestValidateCreate_InvalidRegex verifies rejection of invalid regex pattern.
func TestValidateCreate_InvalidRegex(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Priority: 100,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:    "bad-regex",
					Trigger: panoptiumiov1alpha1.Trigger{EventCategory: "syscall"},
					Action: panoptiumiov1alpha1.Action{
						Type:       panoptiumiov1alpha1.ActionTypeDeny,
						Parameters: map[string]string{"pattern": "[invalid(regex"},
					},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Error("ValidateCreate() error = nil, want rejection for invalid regex")
	}
}

// TestValidateCreate_MissingRules verifies rejection when rules are missing.
func TestValidateCreate_MissingRules(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Priority: 100,
			Rules:    []panoptiumiov1alpha1.PolicyRule{},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Error("ValidateCreate() error = nil, want rejection for missing rules")
	}
}

// TestValidateCreate_EmptyTargetSelectorWarning verifies warning for empty selector.
func TestValidateCreate_EmptyTargetSelectorWarning(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{},
			Priority:       100,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:     "r",
					Trigger:  panoptiumiov1alpha1.Trigger{EventCategory: "s"},
					Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	warnings, err := v.ValidateCreate(context.Background(), policy)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil (warning only, not rejection)", err)
	}
	if len(warnings) == 0 {
		t.Error("ValidateCreate() warnings = none, want warning for empty targetSelector")
	}
}

// TestValidateCreate_ValidCEL verifies valid CEL expressions pass validation.
func TestValidateCreate_ValidCEL(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	policy := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Priority: 100,
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:    "valid-cel",
					Trigger: panoptiumiov1alpha1.Trigger{EventCategory: "syscall"},
					Predicates: []panoptiumiov1alpha1.Predicate{
						{CEL: "1 + 2 == 3"},
					},
					Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), policy)
	if err != nil {
		t.Errorf("ValidateCreate() error = %v, want nil for valid CEL", err)
	}
}

// TestValidateUpdate verifies that update validation works the same as create.
func TestValidateUpdate(t *testing.T) {
	v := &PanoptiumPolicyValidator{}
	old := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			Priority: 100,
		},
	}
	new := &panoptiumiov1alpha1.PanoptiumPolicy{
		Spec: panoptiumiov1alpha1.PanoptiumPolicySpec{
			TargetSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "agent"},
			},
			Priority: 1001, // Invalid
			Rules: []panoptiumiov1alpha1.PolicyRule{
				{
					Name:     "r",
					Trigger:  panoptiumiov1alpha1.Trigger{EventCategory: "s"},
					Action:   panoptiumiov1alpha1.Action{Type: panoptiumiov1alpha1.ActionTypeDeny},
					Severity: panoptiumiov1alpha1.SeverityHigh,
				},
			},
		},
	}

	_, err := v.ValidateUpdate(context.Background(), old, new)
	if err == nil {
		t.Error("ValidateUpdate() error = nil, want rejection for invalid priority")
	}
}
