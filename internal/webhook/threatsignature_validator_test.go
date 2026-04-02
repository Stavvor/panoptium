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
	"k8s.io/apimachinery/pkg/runtime"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// TestThreatSignatureValidator_ValidSignature verifies a valid signature is accepted.
func TestThreatSignatureValidator_ValidSignature(t *testing.T) {
	v := &ThreatSignatureValidator{}

	sig := &panoptiumiov1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "test-valid"},
		Spec: panoptiumiov1alpha1.ThreatSignatureSpec{
			Protocols:   []string{"mcp"},
			Category:    "prompt_injection",
			Severity:    panoptiumiov1alpha1.SeverityHigh,
			Description: "Valid test signature",
			Detection: panoptiumiov1alpha1.DetectionSpec{
				Patterns: []panoptiumiov1alpha1.PatternRule{
					{
						Regex:  `(?i)ignore\s+previous\s+instructions`,
						Weight: 0.9,
						Target: "tool_description",
					},
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), sig)
	if err != nil {
		t.Fatalf("ValidateCreate() error = %v, want nil for valid signature", err)
	}
}

// TestThreatSignatureValidator_InvalidRegex verifies invalid regex is rejected.
func TestThreatSignatureValidator_InvalidRegex(t *testing.T) {
	v := &ThreatSignatureValidator{}

	sig := &panoptiumiov1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "test-bad-regex"},
		Spec: panoptiumiov1alpha1.ThreatSignatureSpec{
			Protocols:   []string{"mcp"},
			Category:    "prompt_injection",
			Severity:    panoptiumiov1alpha1.SeverityHigh,
			Description: "Bad regex signature",
			Detection: panoptiumiov1alpha1.DetectionSpec{
				Patterns: []panoptiumiov1alpha1.PatternRule{
					{
						Regex:  `(?i)ignore\s+(`, // unclosed group
						Weight: 0.9,
						Target: "tool_description",
					},
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), sig)
	if err == nil {
		t.Fatal("ValidateCreate() expected error for invalid regex, got nil")
	}
}

// TestThreatSignatureValidator_InvalidCEL verifies invalid CEL expression is rejected.
func TestThreatSignatureValidator_InvalidCEL(t *testing.T) {
	v := &ThreatSignatureValidator{}

	sig := &panoptiumiov1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "test-bad-cel"},
		Spec: panoptiumiov1alpha1.ThreatSignatureSpec{
			Protocols:   []string{"mcp"},
			Category:    "prompt_injection",
			Severity:    panoptiumiov1alpha1.SeverityHigh,
			Description: "Bad CEL signature",
			Detection: panoptiumiov1alpha1.DetectionSpec{
				CEL: []panoptiumiov1alpha1.CELRule{
					{
						Expression: `this is not valid CEL {{}}`,
						Weight:     0.8,
					},
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), sig)
	if err == nil {
		t.Fatal("ValidateCreate() expected error for invalid CEL, got nil")
	}
}

// TestThreatSignatureValidator_InvalidTarget verifies invalid target value is rejected.
func TestThreatSignatureValidator_InvalidTarget(t *testing.T) {
	v := &ThreatSignatureValidator{}

	sig := &panoptiumiov1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "test-bad-target"},
		Spec: panoptiumiov1alpha1.ThreatSignatureSpec{
			Protocols:   []string{"mcp"},
			Category:    "prompt_injection",
			Severity:    panoptiumiov1alpha1.SeverityHigh,
			Description: "Bad target signature",
			Detection: panoptiumiov1alpha1.DetectionSpec{
				Patterns: []panoptiumiov1alpha1.PatternRule{
					{
						Regex:  `test`,
						Weight: 0.9,
						Target: "invalid_target", // not a valid target
					},
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), sig)
	if err == nil {
		t.Fatal("ValidateCreate() expected error for invalid target, got nil")
	}
}

// TestThreatSignatureValidator_ValidateUpdate verifies update validation works.
func TestThreatSignatureValidator_ValidateUpdate(t *testing.T) {
	v := &ThreatSignatureValidator{}

	sig := &panoptiumiov1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "test-update"},
		Spec: panoptiumiov1alpha1.ThreatSignatureSpec{
			Protocols:   []string{"mcp"},
			Category:    "prompt_injection",
			Severity:    panoptiumiov1alpha1.SeverityHigh,
			Description: "Update test signature",
			Detection: panoptiumiov1alpha1.DetectionSpec{
				Patterns: []panoptiumiov1alpha1.PatternRule{
					{
						Regex:  `(?i)valid\s+pattern`,
						Weight: 0.9,
						Target: "tool_description",
					},
				},
			},
		},
	}

	_, err := v.ValidateUpdate(context.Background(), nil, sig)
	if err != nil {
		t.Fatalf("ValidateUpdate() error = %v, want nil for valid update", err)
	}
}

// TestThreatSignatureValidator_ValidateDelete verifies delete always succeeds.
func TestThreatSignatureValidator_ValidateDelete(t *testing.T) {
	v := &ThreatSignatureValidator{}

	sig := &panoptiumiov1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "test-delete"},
	}

	_, err := v.ValidateDelete(context.Background(), sig)
	if err != nil {
		t.Fatalf("ValidateDelete() error = %v, want nil", err)
	}
}

// TestThreatSignatureValidator_EmptyCategory verifies empty category is rejected.
func TestThreatSignatureValidator_EmptyCategory(t *testing.T) {
	v := &ThreatSignatureValidator{}

	sig := &panoptiumiov1alpha1.ThreatSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "test-empty-cat"},
		Spec: panoptiumiov1alpha1.ThreatSignatureSpec{
			Protocols:   []string{"mcp"},
			Category:    "", // empty
			Severity:    panoptiumiov1alpha1.SeverityHigh,
			Description: "Empty category",
			Detection: panoptiumiov1alpha1.DetectionSpec{
				Patterns: []panoptiumiov1alpha1.PatternRule{
					{Regex: `test`, Weight: 0.5, Target: "body"},
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), sig)
	if err == nil {
		t.Fatal("ValidateCreate() expected error for empty category, got nil")
	}
}

// TestThreatSignatureValidator_WrongType verifies non-ThreatSignature object is rejected.
func TestThreatSignatureValidator_WrongType(t *testing.T) {
	v := &ThreatSignatureValidator{}

	wrong := &runtime.Unknown{}
	_, err := v.ValidateCreate(context.Background(), wrong)
	if err == nil {
		t.Fatal("ValidateCreate() expected error for wrong type, got nil")
	}
}
