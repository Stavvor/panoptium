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

// ResourceUsageSpec defines baseline resource usage expectations for an agent.
type ResourceUsageSpec struct {
	// CPUMillicores is the expected baseline CPU usage in millicores.
	// +optional
	CPUMillicores int32 `json:"cpuMillicores,omitempty"`

	// MemoryMB is the expected baseline memory usage in megabytes.
	// +optional
	MemoryMB int32 `json:"memoryMB,omitempty"`

	// NetworkBandwidthKBps is the expected baseline network bandwidth in kilobytes per second.
	// +optional
	NetworkBandwidthKBps int32 `json:"networkBandwidthKBps,omitempty"`
}

// BaselineSpec defines the behavioral baselines for an agent profile.
type BaselineSpec struct {
	// ExpectedToolCalls is the list of tool/function names the agent normally invokes.
	// +optional
	ExpectedToolCalls []string `json:"expectedToolCalls,omitempty"`

	// NormalResourceUsage defines expected CPU, memory, and network bandwidth baselines.
	// +optional
	NormalResourceUsage ResourceUsageSpec `json:"normalResourceUsage,omitempty"`

	// TypicalNetworkDestinations is the list of expected egress destinations
	// (hostnames or CIDRs) the agent normally communicates with.
	// +optional
	TypicalNetworkDestinations []string `json:"typicalNetworkDestinations,omitempty"`

	// MaxRequestsPerMinute is the expected request rate ceiling for this agent.
	// +optional
	// +kubebuilder:validation:Minimum=0
	MaxRequestsPerMinute int32 `json:"maxRequestsPerMinute,omitempty"`
}

// AgentProfileSpec defines the desired state of a AgentProfile.
type AgentProfileSpec struct {
	// AgentSelector selects the agent pods this profile describes.
	// +kubebuilder:validation:Required
	AgentSelector metav1.LabelSelector `json:"agentSelector"`

	// AgentType is a classification label for the agent (e.g., "coding-assistant",
	// "data-analyst", "autonomous-agent").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	AgentType string `json:"agentType"`

	// Baselines defines the expected behavioral baselines for agents matching this profile.
	// +optional
	Baselines BaselineSpec `json:"baselines,omitempty"`

	// LearningMode indicates whether the profile is in learning mode.
	// When true, baselines are auto-updated based on observed behavior.
	// +optional
	// +kubebuilder:default=false
	LearningMode bool `json:"learningMode,omitempty"`
}

// AgentProfileStatus defines the observed state of a AgentProfile.
type AgentProfileStatus struct {
	// Conditions represent the latest available observations of the profile's state.
	// Supported condition types: Ready, Learning, BaselineEstablished.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// BaselineHealth indicates the current health of the baselines.
	// Values: healthy, degraded, learning.
	// +optional
	BaselineHealth string `json:"baselineHealth,omitempty"`

	// LastBaselineUpdate is the timestamp of the last baseline update.
	// +optional
	LastBaselineUpdate *metav1.Time `json:"lastBaselineUpdate,omitempty"`

	// MatchingAgents is the number of agent pods matching the agentSelector.
	// +optional
	MatchingAgents int32 `json:"matchingAgents,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.agentType`,description="Agent type"
// +kubebuilder:printcolumn:name="Learning",type=boolean,JSONPath=`.spec.learningMode`,description="Learning mode"
// +kubebuilder:printcolumn:name="Health",type=string,JSONPath=`.status.baselineHealth`,description="Baseline health"
// +kubebuilder:printcolumn:name="Agents",type=integer,JSONPath=`.status.matchingAgents`,description="Matching agents"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AgentProfile is the Schema for the agentprofiles API.
// It defines behavioral baselines for AI agent pods, enabling anomaly detection
// by establishing expected patterns of tool calls, resource usage, and network activity.
type AgentProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired agent profile configuration.
	Spec AgentProfileSpec `json:"spec,omitempty"`

	// Status reflects the observed state of the agent profile.
	Status AgentProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AgentProfileList contains a list of AgentProfile resources.
type AgentProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AgentProfile{}, &AgentProfileList{})
}
