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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterPanoptiumPolicySpec defines the desired state of a ClusterPanoptiumPolicy.
// It uses the same fields as PanoptiumPolicySpec and serves as cluster-wide default
// policies that apply to all namespaces unless overridden by namespace-scoped
// PanoptiumPolicy with higher priority.
type ClusterPanoptiumPolicySpec struct {
	// TargetSelector selects the pods this policy applies to across all namespaces.
	// +kubebuilder:validation:Required
	TargetSelector metav1.LabelSelector `json:"targetSelector"`

	// EnforcementMode controls whether actions are enforced, audited, or disabled.
	// +kubebuilder:validation:Required
	// +kubebuilder:default=audit
	EnforcementMode EnforcementMode `json:"enforcementMode"`

	// Priority determines evaluation order when multiple policies match the same pod.
	// Higher priority policies override lower ones on conflict. Range: 1-1000.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	Priority int32 `json:"priority"`

	// Rules is the list of trigger-predicate-action rules evaluated by this policy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Rules []PolicyRule `json:"rules"`
}

// ClusterPanoptiumPolicyStatus defines the observed state of a ClusterPanoptiumPolicy.
type ClusterPanoptiumPolicyStatus struct {
	// Conditions represent the latest available observations of the policy's state.
	// Supported condition types: Ready, Enforcing, Degraded, Error.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// RuleCount is the number of compiled rules in this policy.
	// +optional
	RuleCount int32 `json:"ruleCount,omitempty"`

	// MatchingPods is the number of pods currently matching the targetSelector.
	// +optional
	MatchingPods int32 `json:"matchingPods,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Enforcement",type=string,JSONPath=`.spec.enforcementMode`,description="Enforcement mode"
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`,description="Policy priority"
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.ruleCount`,description="Number of rules"
// +kubebuilder:printcolumn:name="Pods",type=integer,JSONPath=`.status.matchingPods`,description="Matching pods"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterPanoptiumPolicy is the Schema for the clusterpanoptiumpolicies API.
// It defines cluster-scoped security policies with trigger-predicate-action rules
// that apply as defaults across all namespaces unless overridden by namespace-scoped
// PanoptiumPolicy resources with higher priority.
type ClusterPanoptiumPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired policy configuration.
	Spec ClusterPanoptiumPolicySpec `json:"spec,omitempty"`

	// Status reflects the observed state of the policy.
	Status ClusterPanoptiumPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterPanoptiumPolicyList contains a list of ClusterPanoptiumPolicy resources.
type ClusterPanoptiumPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterPanoptiumPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterPanoptiumPolicy{}, &ClusterPanoptiumPolicyList{})
}
