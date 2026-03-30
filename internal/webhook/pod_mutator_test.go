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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestPodMutator_SkipExcludedNamespace verifies pods in kube-system are not modified.
func TestPodMutator_SkipExcludedNamespace(t *testing.T) {
	m := &PodMutator{
		ExcludedNamespaces: []string{"kube-system"},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-pod",
			Namespace: "kube-system",
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Errorf("Default() error = %v", err)
	}

	if pod.Labels != nil && pod.Labels[MonitoredLabel] == "true" {
		t.Error("Pod in kube-system should not be labeled")
	}
}

// TestPodMutator_SkipAlreadyLabeled verifies idempotence - already labeled pods are not re-labeled.
func TestPodMutator_SkipAlreadyLabeled(t *testing.T) {
	m := &PodMutator{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "already-labeled",
			Namespace: "default",
			Labels: map[string]string{
				MonitoredLabel: "true",
				"original":    "preserved",
			},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Errorf("Default() error = %v", err)
	}

	if pod.Labels["original"] != "preserved" {
		t.Error("Original labels should be preserved")
	}
}

// TestPodMutator_InjectSidecar verifies sidecar container injection.
func TestPodMutator_InjectSidecar(t *testing.T) {
	m := &PodMutator{
		SidecarImage: "panoptium/sidecar:test",
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sidecar-test",
			Namespace: "default",
			Labels: map[string]string{
				MonitoredLabel: "true",
			},
			Annotations: map[string]string{
				InjectSidecarAnnotation: "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "main", Image: "app:latest"},
			},
		},
	}

	// Already labeled, so no policy check needed — but the sidecar check
	// only happens when the monitored label is being newly added.
	// Let's test the injection function directly.
	m.injectSidecar(pod)

	if len(pod.Spec.Containers) != 2 {
		t.Fatalf("Expected 2 containers, got %d", len(pod.Spec.Containers))
	}

	sidecar := pod.Spec.Containers[1]
	if sidecar.Name != "panoptium-sidecar" {
		t.Errorf("Sidecar name = %q, want %q", sidecar.Name, "panoptium-sidecar")
	}
	if sidecar.Image != "panoptium/sidecar:test" {
		t.Errorf("Sidecar image = %q, want %q", sidecar.Image, "panoptium/sidecar:test")
	}
}

// TestPodMutator_DefaultExcludedNamespaces verifies default excluded namespaces.
func TestPodMutator_DefaultExcludedNamespaces(t *testing.T) {
	m := &PodMutator{}

	ns := m.excludedNamespaces()
	if len(ns) != 1 || ns[0] != "kube-system" {
		t.Errorf("excludedNamespaces() = %v, want [kube-system]", ns)
	}
}

// TestPodMutator_CustomExcludedNamespaces verifies custom excluded namespaces.
func TestPodMutator_CustomExcludedNamespaces(t *testing.T) {
	m := &PodMutator{
		ExcludedNamespaces: []string{"kube-system", "monitoring"},
	}

	ns := m.excludedNamespaces()
	if len(ns) != 2 {
		t.Errorf("excludedNamespaces() length = %d, want 2", len(ns))
	}
}

// TestPodMutator_NoClient verifies graceful handling when client is nil.
func TestPodMutator_NoClient(t *testing.T) {
	m := &PodMutator{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-client-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "test"},
		},
	}

	err := m.Default(context.Background(), pod)
	if err != nil {
		t.Errorf("Default() error = %v, want nil when client is nil", err)
	}

	// Should not add label when client is nil (can't check policies)
	if pod.Labels[MonitoredLabel] == "true" {
		t.Error("Should not label when client is nil")
	}
}
