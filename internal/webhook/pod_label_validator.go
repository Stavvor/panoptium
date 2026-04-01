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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
)

// PodLabelValidator is a ValidatingWebhook for pods that prevents removal of
// the panoptium.io/monitored=true label when a matching PanoptiumPolicy exists
// in the namespace. This prevents enrollment bypass via kubectl label removal.
type PodLabelValidator struct {
	Client client.Client

	// ExcludedNamespaces is the list of namespaces where label protection
	// is not enforced. Defaults to ["kube-system"].
	ExcludedNamespaces []string
}

// SetupWebhookWithManager registers the validating webhook with the manager.
func (v *PodLabelValidator) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&corev1.Pod{}).
		WithValidator(v).
		Complete()
}

// ValidateCreate allows all pod creation (mutation handles enrollment).
func (v *PodLabelValidator) ValidateCreate(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// ValidateUpdate checks if the panoptium.io/monitored label is being removed
// and blocks the operation if a matching PanoptiumPolicy exists.
func (v *PodLabelValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldPod, ok := oldObj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected Pod but got %T", oldObj)
	}

	newPod, ok := newObj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected Pod but got %T", newObj)
	}

	logger := log.FromContext(ctx)

	// Skip excluded namespaces
	for _, ns := range v.excludedNamespaces() {
		if newPod.Namespace == ns {
			return nil, nil
		}
	}

	// Check if the monitored label is being removed
	oldHasLabel := oldPod.Labels != nil && oldPod.Labels[MonitoredLabel] == "true"
	newHasLabel := newPod.Labels != nil && newPod.Labels[MonitoredLabel] == "true"

	if !oldHasLabel || newHasLabel {
		// Label was not present before, or is still present — allow
		return nil, nil
	}

	// Label is being removed — check if a matching policy exists
	if v.Client == nil {
		// Fail-closed: if we can't check policies, block the removal
		return nil, fmt.Errorf("cannot validate label removal: kubernetes client is unavailable")
	}

	policies := &panoptiumiov1alpha1.PanoptiumPolicyList{}
	if err := v.Client.List(ctx, policies, client.InNamespace(newPod.Namespace)); err != nil {
		logger.Error(err, "failed to list policies for label protection check")
		return nil, fmt.Errorf("failed to check policies: %w", err)
	}

	for _, policy := range policies.Items {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.TargetSelector)
		if err != nil {
			continue
		}
		// Check against the pod's original labels (before removal) to determine
		// if it was under policy scope
		if selector.Matches(labels.Set(oldPod.Labels)) {
			logger.Info("Blocked removal of monitored label",
				"pod", newPod.Name,
				"namespace", newPod.Namespace,
				"policy", policy.Name)
			return nil, fmt.Errorf(
				"removal of label %q is not allowed: pod matches PanoptiumPolicy %q",
				MonitoredLabel, policy.Name,
			)
		}
	}

	// No matching policy — allow the removal
	return nil, nil
}

// ValidateDelete allows all pod deletion.
func (v *PodLabelValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// excludedNamespaces returns the list of excluded namespaces, defaulting to kube-system.
func (v *PodLabelValidator) excludedNamespaces() []string {
	if len(v.ExcludedNamespaces) > 0 {
		return v.ExcludedNamespaces
	}
	return []string{"kube-system"}
}
