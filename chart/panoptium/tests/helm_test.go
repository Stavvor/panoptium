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

package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func chartPath(t *testing.T) string {
	t.Helper()
	// Find the chart directory relative to this test file
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	return filepath.Join(wd, "..")
}

func helmTemplate(t *testing.T, args ...string) string {
	t.Helper()
	baseArgs := []string{"template", "panoptium", chartPath(t)}
	baseArgs = append(baseArgs, args...)
	cmd := exec.Command("helm", baseArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, string(out))
	}
	return string(out)
}

// TestHelmLint verifies the chart passes helm lint.
func TestHelmLint(t *testing.T) {
	cmd := exec.Command("helm", "lint", chartPath(t), "--strict")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm lint failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "0 chart(s) failed") {
		t.Fatalf("helm lint reported failures:\n%s", string(out))
	}
}

// TestHelmTemplate_DefaultValues verifies the chart renders with default values.
func TestHelmTemplate_DefaultValues(t *testing.T) {
	output := helmTemplate(t)

	// Verify essential resources are present
	requiredKinds := []string{
		"kind: ServiceAccount",
		"kind: ClusterRole",
		"kind: ClusterRoleBinding",
		"kind: Role",
		"kind: RoleBinding",
		"kind: Service",
		"kind: Deployment",
		"kind: ValidatingWebhookConfiguration",
		"kind: MutatingWebhookConfiguration",
	}
	for _, kind := range requiredKinds {
		if !strings.Contains(output, kind) {
			t.Errorf("missing %s in default template output", kind)
		}
	}

	// Verify no DaemonSet by default (observer.enabled=false)
	if strings.Contains(output, "kind: DaemonSet") {
		t.Error("DaemonSet should not be rendered when observer.enabled=false")
	}
}

// TestHelmTemplate_CRDs verifies all 5 CRDs are included.
func TestHelmTemplate_CRDs(t *testing.T) {
	output := helmTemplate(t, "--include-crds")

	crds := []string{
		"panoptiumpolicies.panoptium.io",
		"clusterpanoptiumpolicies.panoptium.io",
		"panoptiumagentprofiles.panoptium.io",
		"panoptiumthreatsignatures.panoptium.io",
		"panoptiumquarantines.panoptium.io",
	}
	for _, crd := range crds {
		if !strings.Contains(output, crd) {
			t.Errorf("missing CRD %s in template output", crd)
		}
	}
}

// TestHelmTemplate_WebhookDisabled verifies webhook resources are excluded
// when webhook.enabled=false.
func TestHelmTemplate_WebhookDisabled(t *testing.T) {
	output := helmTemplate(t, "--set", "webhook.enabled=false")

	if strings.Contains(output, "ValidatingWebhookConfiguration") {
		t.Error("ValidatingWebhookConfiguration should not be rendered when webhook.enabled=false")
	}
	if strings.Contains(output, "MutatingWebhookConfiguration") {
		t.Error("MutatingWebhookConfiguration should not be rendered when webhook.enabled=false")
	}
	if strings.Contains(output, "webhook-service") {
		t.Error("webhook service should not be rendered when webhook.enabled=false")
	}
}

// TestHelmTemplate_ObserverEnabled verifies the observer DaemonSet is rendered
// when observer.enabled=true.
func TestHelmTemplate_ObserverEnabled(t *testing.T) {
	output := helmTemplate(t, "--set", "observer.enabled=true")

	if !strings.Contains(output, "kind: DaemonSet") {
		t.Error("DaemonSet should be rendered when observer.enabled=true")
	}
	if !strings.Contains(output, "app.kubernetes.io/component: observer") {
		t.Error("observer component label should be present")
	}
}

// TestHelmTemplate_CustomValues verifies that custom values are applied.
func TestHelmTemplate_CustomValues(t *testing.T) {
	output := helmTemplate(t,
		"--set", "replicaCount=3",
		"--set", "image.tag=v1.0.0",
		"--set", "extproc.port=9999",
	)

	if !strings.Contains(output, "replicas: 3") {
		t.Error("replicaCount override not applied")
	}
	if !strings.Contains(output, "ghcr.io/panoptium/panoptium:v1.0.0") {
		t.Error("image.tag override not applied")
	}
	if !strings.Contains(output, "--extproc-port=9999") {
		t.Error("extproc.port override not applied")
	}
}

// TestHelmTemplate_RBAC verifies that ClusterRole includes all required
// permissions for the five CRDs plus supporting resources.
func TestHelmTemplate_RBAC(t *testing.T) {
	output := helmTemplate(t)

	requiredResources := []string{
		"panoptiumpolicies",
		"clusterpanoptiumpolicies",
		"panoptiumagentprofiles",
		"panoptiumthreatsignatures",
		"panoptiumquarantines",
		"networkpolicies",
		"pods",
		"pods/eviction",
		"events",
	}
	for _, resource := range requiredResources {
		if !strings.Contains(output, resource) {
			t.Errorf("RBAC missing resource: %s", resource)
		}
	}
}

// TestHelmTemplate_MutatingWebhookFailurePolicy verifies the mutating webhook
// uses failurePolicy=Fail to prevent unmonitored pod creation when webhook is unavailable.
func TestHelmTemplate_MutatingWebhookFailurePolicy(t *testing.T) {
	output := helmTemplate(t, "--set", "webhook.enabled=true", "--set", "webhook.certManager=true")

	// The failurePolicy must be Fail (not Ignore) to prevent bypassing enrollment
	if !strings.Contains(output, "failurePolicy: Fail") {
		t.Error("mutating webhook failurePolicy should be Fail, not Ignore")
	}
	if strings.Contains(output, "failurePolicy: Ignore") {
		t.Error("mutating webhook must not use failurePolicy: Ignore (security vulnerability)")
	}
}

// TestHelmTemplate_MutatingWebhookOperations verifies the mutating webhook
// intercepts both CREATE and UPDATE operations on pods.
func TestHelmTemplate_MutatingWebhookOperations(t *testing.T) {
	output := helmTemplate(t, "--set", "webhook.enabled=true", "--set", "webhook.certManager=true")

	// Extract the MutatingWebhookConfiguration section specifically
	mutatingIdx := strings.Index(output, "kind: MutatingWebhookConfiguration")
	if mutatingIdx < 0 {
		t.Fatal("MutatingWebhookConfiguration not found in template output")
	}
	// Find the next document separator or EOF
	rest := output[mutatingIdx:]
	endIdx := strings.Index(rest, "\n---\n")
	if endIdx > 0 {
		rest = rest[:endIdx]
	}

	// Within the MutatingWebhookConfiguration, check that pod operations include UPDATE
	if !strings.Contains(rest, "operations: [CREATE, UPDATE]") {
		t.Error("mutating webhook operations for pods should include both CREATE and UPDATE to prevent enrollment bypass via label removal")
	}
}

// TestHelmTemplate_SecurityContext verifies security hardening is applied.
func TestHelmTemplate_SecurityContext(t *testing.T) {
	output := helmTemplate(t)

	if !strings.Contains(output, "runAsNonRoot: true") {
		t.Error("runAsNonRoot should be set")
	}
	if !strings.Contains(output, "allowPrivilegeEscalation: false") {
		t.Error("allowPrivilegeEscalation should be false")
	}
	if !strings.Contains(output, "readOnlyRootFilesystem: true") {
		t.Error("readOnlyRootFilesystem should be true")
	}
}
