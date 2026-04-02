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

const (
	// QuarantineCleanupFinalizer is the finalizer added to AgentQuarantine resources
	// to ensure NetworkPolicies and BPF-LSM rules are cleaned up before deletion.
	QuarantineCleanupFinalizer = "panoptium.io/quarantine-cleanup"
)

// ContainmentLevel defines the graduated containment level for a quarantined pod.
// +kubebuilder:validation:Enum=network-isolate;syscall-restrict;freeze;evict
type ContainmentLevel string

const (
	// ContainmentLevelNetworkIsolate applies NetworkPolicy-based network isolation.
	ContainmentLevelNetworkIsolate ContainmentLevel = "network-isolate"

	// ContainmentLevelSyscallRestrict applies BPF-LSM syscall restrictions.
	ContainmentLevelSyscallRestrict ContainmentLevel = "syscall-restrict"

	// ContainmentLevelFreeze halts all pod activity while preserving state.
	ContainmentLevelFreeze ContainmentLevel = "freeze"

	// ContainmentLevelEvict terminates and removes the pod.
	ContainmentLevelEvict ContainmentLevel = "evict"
)

// ResolutionSpec defines how and when a quarantine should be resolved.
type ResolutionSpec struct {
	// AutoRelease indicates whether the quarantine should be automatically released
	// after the TTL expires.
	// +optional
	// +kubebuilder:default=false
	AutoRelease bool `json:"autoRelease,omitempty"`

	// TTLSeconds is the time-to-live in seconds for auto-release.
	// Only used when AutoRelease is true.
	// +optional
	// +kubebuilder:validation:Minimum=0
	TTLSeconds int32 `json:"ttlSeconds,omitempty"`

	// ManualApprovalRequired indicates that a human must explicitly approve
	// the release of this quarantine.
	// +optional
	// +kubebuilder:default=false
	ManualApprovalRequired bool `json:"manualApprovalRequired,omitempty"`
}

// ForensicSnapshotSpec defines what forensic data to capture at quarantine time.
type ForensicSnapshotSpec struct {
	// CaptureNetworkState indicates whether to snapshot NetworkPolicies at quarantine time.
	// +optional
	// +kubebuilder:default=true
	CaptureNetworkState bool `json:"captureNetworkState,omitempty"`

	// CaptureProcessTree indicates whether to snapshot running processes at quarantine time.
	// +optional
	// +kubebuilder:default=true
	CaptureProcessTree bool `json:"captureProcessTree,omitempty"`

	// CaptureEnvironment indicates whether to snapshot environment variables (redacted)
	// at quarantine time.
	// +optional
	// +kubebuilder:default=false
	CaptureEnvironment bool `json:"captureEnvironment,omitempty"`
}

// EventReference is a reference to a specific event in the triggering event chain.
type EventReference struct {
	// EventID is the unique identifier of the referenced event.
	// +kubebuilder:validation:Required
	EventID string `json:"eventID"`

	// Timestamp is when the referenced event occurred.
	// +kubebuilder:validation:Required
	Timestamp metav1.Time `json:"timestamp"`

	// Category is the event category (e.g., "syscall", "network", "llm").
	// +kubebuilder:validation:Required
	Category string `json:"category"`

	// Summary is a human-readable summary of the referenced event.
	// +optional
	Summary string `json:"summary,omitempty"`
}

// AgentQuarantineSpec defines the desired state of a AgentQuarantine.
type AgentQuarantineSpec struct {
	// TargetPod is the name of the pod to quarantine.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	TargetPod string `json:"targetPod"`

	// TargetNamespace is the namespace of the target pod.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	TargetNamespace string `json:"targetNamespace"`

	// ContainmentLevel defines the graduated containment level to apply.
	// +kubebuilder:validation:Required
	ContainmentLevel ContainmentLevel `json:"containmentLevel"`

	// Reason is a human-readable reason for this quarantine action.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Reason string `json:"reason"`

	// TriggeringPolicy is the name of the AgentPolicy that triggered this quarantine.
	// +optional
	TriggeringPolicy string `json:"triggeringPolicy,omitempty"`

	// TriggeringSignature is the name of the ThreatSignature that matched.
	// +optional
	TriggeringSignature string `json:"triggeringSignature,omitempty"`

	// Resolution defines how and when this quarantine should be resolved.
	// +optional
	Resolution ResolutionSpec `json:"resolution,omitempty"`

	// ForensicSnapshot defines what forensic data to capture at quarantine time.
	// +optional
	ForensicSnapshot ForensicSnapshotSpec `json:"forensicSnapshot,omitempty"`
}

// AgentQuarantineStatus defines the observed state of a AgentQuarantine.
type AgentQuarantineStatus struct {
	// Conditions represent the latest available observations of the quarantine's state.
	// Supported condition types: Ready, Contained, Released, Error.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// AppliedNetworkPolicies lists the names of NetworkPolicies created for isolation.
	// +optional
	AppliedNetworkPolicies []string `json:"appliedNetworkPolicies,omitempty"`

	// BPFLSMRules lists descriptions of BPF-LSM rules applied for containment.
	// +optional
	BPFLSMRules []string `json:"bpfLSMRules,omitempty"`

	// TriggeringEventChain is the ordered list of events that led to this quarantine.
	// +optional
	TriggeringEventChain []EventReference `json:"triggeringEventChain,omitempty"`

	// ContainedAt is the timestamp when containment was first applied.
	// +optional
	ContainedAt *metav1.Time `json:"containedAt,omitempty"`

	// ReleasedAt is the timestamp when containment was released.
	// +optional
	ReleasedAt *metav1.Time `json:"releasedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.targetPod`,description="Target pod"
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.spec.targetNamespace`,description="Target namespace"
// +kubebuilder:printcolumn:name="Level",type=string,JSONPath=`.spec.containmentLevel`,description="Containment level"
// +kubebuilder:printcolumn:name="Contained",type=string,JSONPath=`.status.conditions[?(@.type=="Contained")].status`,description="Contained status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AgentQuarantine is the Schema for the agentquarantines API.
// It represents a containment action applied to a pod suspected of malicious
// or anomalous behavior. The quarantine includes graduated containment levels,
// resolution policies, and forensic snapshot configuration.
type AgentQuarantine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired quarantine configuration.
	Spec AgentQuarantineSpec `json:"spec,omitempty"`

	// Status reflects the observed state of the quarantine.
	Status AgentQuarantineStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AgentQuarantineList contains a list of AgentQuarantine resources.
type AgentQuarantineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentQuarantine `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AgentQuarantine{}, &AgentQuarantineList{})
}
