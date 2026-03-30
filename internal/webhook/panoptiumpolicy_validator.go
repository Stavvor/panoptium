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

// Package webhook implements admission webhooks for the Panoptium operator.
package webhook

import (
	"context"
	"fmt"
	"regexp"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/google/cel-go/cel"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// PanoptiumPolicyValidator validates PanoptiumPolicy resources on create and update.
// It checks required fields, priority range, CEL expression syntax, and regex patterns.
type PanoptiumPolicyValidator struct{}

var _ webhook.CustomValidator = &PanoptiumPolicyValidator{}

// SetupWebhookWithManager registers the validating webhook with the manager.
func (v *PanoptiumPolicyValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&panoptiumiov1alpha1.PanoptiumPolicy{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate validates a PanoptiumPolicy on creation.
func (v *PanoptiumPolicyValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*panoptiumiov1alpha1.PanoptiumPolicy)
	if !ok {
		return nil, fmt.Errorf("expected PanoptiumPolicy but got %T", obj)
	}
	return validatePolicy(policy)
}

// ValidateUpdate validates a PanoptiumPolicy on update.
func (v *PanoptiumPolicyValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	policy, ok := newObj.(*panoptiumiov1alpha1.PanoptiumPolicy)
	if !ok {
		return nil, fmt.Errorf("expected PanoptiumPolicy but got %T", newObj)
	}
	return validatePolicy(policy)
}

// ValidateDelete validates a PanoptiumPolicy on deletion (no-op).
func (v *PanoptiumPolicyValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// validatePolicy performs all validation checks on a PanoptiumPolicy.
func validatePolicy(policy *panoptiumiov1alpha1.PanoptiumPolicy) (admission.Warnings, error) {
	var allErrs field.ErrorList
	var warnings admission.Warnings

	specPath := field.NewPath("spec")

	// Validate priority range (1-1000)
	if policy.Spec.Priority < 1 || policy.Spec.Priority > 1000 {
		allErrs = append(allErrs, field.Invalid(
			specPath.Child("priority"),
			policy.Spec.Priority,
			"priority must be between 1 and 1000",
		))
	}

	// Validate rules are present
	if len(policy.Spec.Rules) == 0 {
		allErrs = append(allErrs, field.Required(
			specPath.Child("rules"),
			"at least one rule is required",
		))
	}

	// Validate targetSelector has content
	if len(policy.Spec.TargetSelector.MatchLabels) == 0 &&
		len(policy.Spec.TargetSelector.MatchExpressions) == 0 {
		warnings = append(warnings,
			"targetSelector is empty; policy will match all pods which may be unintended")
	}

	// Validate each rule
	rulesPath := specPath.Child("rules")
	for i, rule := range policy.Spec.Rules {
		rulePath := rulesPath.Index(i)

		// Validate rule name
		if rule.Name == "" {
			allErrs = append(allErrs, field.Required(
				rulePath.Child("name"),
				"rule name is required",
			))
		}

		// Validate trigger
		if rule.Trigger.EventCategory == "" {
			allErrs = append(allErrs, field.Required(
				rulePath.Child("trigger", "eventCategory"),
				"trigger eventCategory is required",
			))
		}

		// Validate CEL expressions in predicates
		for j, pred := range rule.Predicates {
			predPath := rulePath.Child("predicates").Index(j)
			if pred.CEL == "" {
				allErrs = append(allErrs, field.Required(
					predPath.Child("cel"),
					"predicate CEL expression is required",
				))
				continue
			}

			if err := validateCELExpression(pred.CEL); err != nil {
				allErrs = append(allErrs, field.Invalid(
					predPath.Child("cel"),
					pred.CEL,
					fmt.Sprintf("invalid CEL expression: %v", err),
				))
			}
		}

		// Validate regex patterns in action parameters
		if rule.Action.Parameters != nil {
			for key, val := range rule.Action.Parameters {
				if key == "pattern" || key == "regex" {
					if _, err := regexp.Compile(val); err != nil {
						allErrs = append(allErrs, field.Invalid(
							rulePath.Child("action", "parameters", key),
							val,
							fmt.Sprintf("invalid regex pattern: %v", err),
						))
					}
				}
			}
		}
	}

	if len(allErrs) > 0 {
		return warnings, allErrs.ToAggregate()
	}
	return warnings, nil
}

// validateCELExpression checks if a CEL expression is syntactically valid.
func validateCELExpression(expr string) error {
	env, err := cel.NewEnv()
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	_, issues := env.Parse(expr)
	if issues != nil && issues.Err() != nil {
		return issues.Err()
	}

	return nil
}
