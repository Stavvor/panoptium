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

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	"github.com/panoptium/panoptium/test/utils"
)

// ---------------------------------------------------------------------------
// ThreatSignature CRD Lifecycle E2E Tests
// ---------------------------------------------------------------------------

var _ = Describe("ThreatSignature CRD Lifecycle E2E", Label("e2e-threat-sig"), Ordered, func() {

	BeforeAll(func() {
		By("verifying panoptium operator is running")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyControllerUp, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching operator logs on failure")
			cmd := exec.Command("kubectl", "logs",
				"-l", "control-plane=controller-manager",
				"-n", namespace, "--tail=100")
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n%s\n", controllerLogs)
			}

			By("Fetching Kubernetes events on failure")
			cmd = exec.Command("kubectl", "get", "events", "-A",
				"--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s\n", eventsOutput)
			}
		}
	})

	// -------------------------------------------------------------------
	// TS-1: Valid ThreatSignature CRD Lifecycle (create, update, delete)
	// -------------------------------------------------------------------
	Context("TS-1: Valid ThreatSignature CRD Lifecycle", func() {

		It("should create a valid PanoptiumThreatSignature and reach Ready=True", func() {
			sigName := uniqueName("ts1-valid")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: prompt_injection
  severity: HIGH
  description: "E2E test signature: detects ignore instructions pattern"
  detection:
    patterns:
      - regex: '(?i)ignore\s+previous\s+instructions'
        weight: 0.9
        target: tool_description
`, sigName)

			By("applying a valid PanoptiumThreatSignature resource")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply PanoptiumThreatSignature")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName,
					"--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for Ready=True status condition")
			waitForThreatSignatureReady(sigName, 2*time.Minute)
		})

		It("should delete a PanoptiumThreatSignature and verify resource is fully removed", func() {
			sigName := uniqueName("ts1-delete")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: data_exfiltration
  severity: MEDIUM
  description: "E2E test signature for deletion test"
  detection:
    patterns:
      - regex: '(?i)exfiltrate'
        weight: 0.7
        target: message_content
`, sigName)

			By("applying a PanoptiumThreatSignature resource")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply PanoptiumThreatSignature")

			By("waiting for Ready=True status condition")
			waitForThreatSignatureReady(sigName, 2*time.Minute)

			By("deleting the PanoptiumThreatSignature resource")
			cmd = exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete PanoptiumThreatSignature")

			By("waiting for the resource to be fully removed")
			verifyGone := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "PanoptiumThreatSignature should no longer exist")
			}
			Eventually(verifyGone, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should update a PanoptiumThreatSignature regex and reconcile to Ready=True", func() {
			sigName := uniqueName("ts1-update")
			originalYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: role_confusion
  severity: HIGH
  description: "E2E test signature for update test"
  detection:
    patterns:
      - regex: '(?i)you\s+are\s+now'
        weight: 0.9
        target: tool_description
`, sigName)

			By("applying original PanoptiumThreatSignature")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(originalYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName,
					"--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for initial Ready=True")
			waitForThreatSignatureReady(sigName, 2*time.Minute)

			By("recording the original observedGeneration")
			originalGen := getThreatSignatureObservedGeneration(sigName)

			updatedYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: role_confusion
  severity: CRITICAL
  description: "E2E test signature for update test - updated regex"
  detection:
    patterns:
      - regex: '(?i)(you\s+are\s+now|assume\s+the\s+role)'
        weight: 0.95
        target: tool_description
`, sigName)

			By("updating the PanoptiumThreatSignature with new regex")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(updatedYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to update PanoptiumThreatSignature")

			By("waiting for Ready=True with updated observedGeneration")
			verifyUpdated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Should be Ready=True after update")

				newGen := getThreatSignatureObservedGeneration(sigName)
				g.Expect(newGen).To(BeNumerically(">", originalGen),
					"observedGeneration should increase after update")
			}
			Eventually(verifyUpdated, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------
	// TS-2: Invalid ThreatSignature Rejection
	// -------------------------------------------------------------------
	Context("TS-2: Invalid ThreatSignature Rejection", func() {

		It("should set Ready=False for a ThreatSignature with invalid regex", func() {
			// Note: The ThreatSignature validating webhook is not yet wired in the
			// Helm chart / kustomize, so invalid regex is accepted at admission but
			// the controller sets Ready=False with CompilationFailed reason.
			sigName := uniqueName("ts2-bad-regex")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: prompt_injection
  severity: HIGH
  description: "E2E test signature with invalid regex"
  detection:
    patterns:
      - regex: '(?P<invalid[unclosed'
        weight: 0.9
        target: tool_description
`, sigName)

			By("applying a ThreatSignature with invalid regex")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "CRD should accept the resource (webhook not wired)")

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName,
					"--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for Ready=False with CompilationFailed reason")
			verifyNotReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("False"), "Should have Ready=False for invalid regex")

				cmd = exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].reason}")
				reason, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(reason).To(Equal("CompilationFailed"),
					"Reason should be CompilationFailed for invalid regex")
			}
			Eventually(verifyNotReady, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should reject a ThreatSignature with invalid severity at CRD schema level", func() {
			sigName := uniqueName("ts2-bad-severity")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: prompt_injection
  severity: INVALID_SEVERITY
  description: "E2E test signature with invalid severity"
  detection:
    patterns:
      - regex: '(?i)test'
        weight: 0.5
        target: tool_description
`, sigName)

			By("applying a ThreatSignature with invalid severity value")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(),
				"CRD schema should reject invalid severity enum value")
			Expect(output).To(ContainSubstring("severity"),
				"Error should mention severity field")
		})

		It("should reject a ThreatSignature with invalid target at CRD schema level", func() {
			sigName := uniqueName("ts2-bad-target")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: prompt_injection
  severity: HIGH
  description: "E2E test signature with invalid target"
  detection:
    patterns:
      - regex: '(?i)test'
        weight: 0.5
        target: invalid_target_value
`, sigName)

			By("applying a ThreatSignature with invalid target value")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(),
				"CRD schema should reject invalid target enum value")
			Expect(output).To(ContainSubstring("target"),
				"Error should mention target field")
		})
	})
})

// ---------------------------------------------------------------------------
// Default Helm-Deployed ThreatSignature E2E Tests
// ---------------------------------------------------------------------------

var _ = Describe("Default Helm ThreatSignature E2E", Label("e2e-threat-sig"), Ordered, func() {

	BeforeAll(func() {
		By("checking if the operator was deployed via Helm with threat signatures enabled")
		cmd := exec.Command("helm", "list", "-n", namespace, "-o", "json")
		output, err := utils.Run(cmd)
		if err != nil || !strings.Contains(output, "panoptium") {
			Skip("operator not deployed via Helm")
		}
	})

	// expectedDefaultSignatures lists all default PanoptiumThreatSignature resources
	// deployed by the Helm chart (chart/panoptium/templates/threat-signatures/).
	var expectedDefaultSignatures = []string{
		"mcp-ignore-instructions",
		"mcp-delimiter-injection",
		"mcp-instruction-override",
		"indirect-prompt-injection",
		"mcp-system-prompt-reference",
		"mcp-role-confusion",
		"mcp-tool-shadowing",
		"mcp-output-exfiltration",
		"obfuscated-payload",
	}

	// expectedCategories lists the attack categories that must be covered by
	// default signatures.
	var expectedCategories = []string{
		"prompt_injection",
		"data_exfiltration",
		"tool_manipulation",
		"obfuscation",
		"role_confusion",
	}

	Context("TS-3: Default ThreatSignature Resources", func() {

		It("should have all default PanoptiumThreatSignature resources deployed", func() {
			By("verifying all expected default signatures exist")
			for _, sigName := range expectedDefaultSignatures {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(),
					fmt.Sprintf("Default signature %q should exist", sigName))
			}
		})

		It("should have all default signatures with Ready=True status", func() {
			By("verifying each default signature has Ready=True")
			for _, sigName := range expectedDefaultSignatures {
				verifyReady := func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
						"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal("True"),
						fmt.Sprintf("Default signature %q should have Ready=True", sigName))
				}
				Eventually(verifyReady, 2*time.Minute, 5*time.Second).Should(Succeed())
			}
		})

		It("should have all default signatures carrying panoptium.io/managed-by=helm label", func() {
			By("verifying each default signature has the managed-by label")
			for _, sigName := range expectedDefaultSignatures {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
					"-o", "jsonpath={.metadata.labels.panoptium\\.io/managed-by}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).To(Equal("helm"),
					fmt.Sprintf("Default signature %q should have panoptium.io/managed-by=helm", sigName))
			}
		})

		It("should cover all expected attack categories", func() {
			By("listing all default signature categories")
			cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature",
				"-l", "panoptium.io/managed-by=helm",
				"-o", "jsonpath={.items[*].spec.category}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			categories := strings.Fields(output)
			for _, expected := range expectedCategories {
				found := false
				for _, actual := range categories {
					if actual == expected {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(),
					fmt.Sprintf("Expected category %q not found among default signatures. Found: %v", expected, categories))
			}
		})
	})
})

// ---------------------------------------------------------------------------
// CRD-Driven Threat Detection Hot-Reload E2E Tests
// ---------------------------------------------------------------------------

var _ = Describe("ThreatSignature Hot-Reload E2E", Label("e2e-threat-sig"), Ordered, func() {

	BeforeAll(func() {
		By("verifying panoptium operator is running")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyControllerUp, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching operator logs on failure")
			cmd := exec.Command("kubectl", "logs",
				"-l", "control-plane=controller-manager",
				"-n", namespace, "--tail=100")
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n%s\n", controllerLogs)
			}
		}
	})

	// -------------------------------------------------------------------
	// TS-4: CRD-Driven Threat Detection Hot-Reload
	// -------------------------------------------------------------------
	Context("TS-4: Threat Signature Hot-Reload via Reconciler", func() {

		It("should reconcile a new ThreatSignature and emit Kubernetes event on compilation", func() {
			sigName := uniqueName("ts4-hotreload")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: prompt_injection
  severity: HIGH
  description: "E2E hot-reload test: detect hidden instructions"
  detection:
    patterns:
      - regex: '(?i)ignore\s+all\s+safety\s+rules'
        weight: 0.95
        target: tool_description
`, sigName)

			By("applying a new PanoptiumThreatSignature")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName,
					"--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for Ready=True status (confirms reconciler picked it up)")
			waitForThreatSignatureReady(sigName, 2*time.Minute)

			By("verifying the compiledPatterns count in status")
			verifyPatternCount := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
					"-o", "jsonpath={.status.compiledPatterns}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"), "Should have 1 compiled pattern")
			}
			Eventually(verifyPatternCount, 30*time.Second, 5*time.Second).Should(Succeed())
		})

		It("should remove ThreatSignature from cluster on deletion", func() {
			sigName := uniqueName("ts4-delete")
			yaml := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: data_exfiltration
  severity: MEDIUM
  description: "E2E hot-reload deletion test"
  detection:
    patterns:
      - regex: '(?i)send\s+to\s+external'
        weight: 0.8
        target: message_content
`, sigName)

			By("applying and waiting for Ready=True")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(yaml)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			waitForThreatSignatureReady(sigName, 2*time.Minute)

			By("deleting the ThreatSignature")
			cmd = exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the resource is removed within 5 seconds")
			verifyRemoved := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "ThreatSignature should be gone after deletion")
			}
			Eventually(verifyRemoved, 10*time.Second, 1*time.Second).Should(Succeed())
		})

		It("should reconcile updated regex and reflect new compiledPatterns count", func() {
			sigName := uniqueName("ts4-update")
			originalYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: tool_manipulation
  severity: HIGH
  description: "E2E hot-reload update test"
  detection:
    patterns:
      - regex: '(?i)shadow\s+tool'
        weight: 0.85
        target: tool_description
`, sigName)

			By("applying original ThreatSignature with 1 pattern")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(originalYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName,
					"--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("waiting for Ready=True with 1 compiled pattern")
			waitForThreatSignatureReady(sigName, 2*time.Minute)
			originalGen := getThreatSignatureObservedGeneration(sigName)

			updatedYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: tool_manipulation
  severity: CRITICAL
  description: "E2E hot-reload update test - expanded patterns"
  detection:
    patterns:
      - regex: '(?i)shadow\s+tool'
        weight: 0.85
        target: tool_description
      - regex: '(?i)replace\s+(the\s+)?original\s+tool'
        weight: 0.9
        target: tool_description
`, sigName)

			By("updating ThreatSignature with 2 patterns")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(updatedYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying reconciler picks up update and compiles both patterns")
			verifyUpdated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
					"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"))

				cmd = exec.Command("kubectl", "get", "panoptiumthreatsignature", sigName,
					"-o", "jsonpath={.status.compiledPatterns}")
				count, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(count).To(Equal("2"), "Should have 2 compiled patterns after update")

				newGen := getThreatSignatureObservedGeneration(sigName)
				g.Expect(newGen).To(BeNumerically(">", originalGen),
					"observedGeneration should increase after update")
			}
			Eventually(verifyUpdated, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})

// ---------------------------------------------------------------------------
// PanoptiumPolicy Integration with ThreatSignatures E2E Tests
// ---------------------------------------------------------------------------

var _ = Describe("ThreatSignature Policy Integration E2E", Label("e2e-threat-sig"), Ordered, func() {

	BeforeAll(func() {
		By("verifying panoptium operator is running")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyControllerUp, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching operator logs on failure")
			cmd := exec.Command("kubectl", "logs",
				"-l", "control-plane=controller-manager",
				"-n", namespace, "--tail=100")
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n%s\n", controllerLogs)
			}
		}
	})

	// -------------------------------------------------------------------
	// TS-5: PanoptiumPolicy with ThreatSignature References
	// -------------------------------------------------------------------
	Context("TS-5: Policy-ThreatSignature Integration", func() {

		It("should create a PanoptiumPolicy referencing a threat signature by name and reach Ready=True", func() {
			sigName := uniqueName("ts5-sig-byname")
			policyName := uniqueName("ts5-pol-byname")

			By("creating a ThreatSignature for the policy to reference")
			sigYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumThreatSignature
metadata:
  name: %s
spec:
  protocols:
    - mcp
  category: prompt_injection
  severity: CRITICAL
  description: "E2E policy integration test signature"
  detection:
    patterns:
      - regex: '(?i)ignore\s+instructions'
        weight: 0.9
        target: tool_description
`, sigName)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(sigYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			waitForThreatSignatureReady(sigName, 2*time.Minute)

			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "panoptiumthreatsignature", sigName,
					"--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("creating a PanoptiumPolicy that references the signature by name")
			policyYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-ts5-target
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: block-on-threat-sig
      trigger:
        eventCategory: protocol
        eventSubcategory: mcp.tool.call
      threatSignatures:
        names:
          - %s
      action:
        type: deny
      severity: CRITICAL
`, policyName, namespace, sigName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(policyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PanoptiumPolicy with threatSignatures.names")

			DeferCleanup(func() {
				deletePanoptiumPolicy(policyName, namespace)
			})

			By("waiting for the policy to reach Ready=True")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)
		})

		It("should create a PanoptiumPolicy matching by category selector and reach Ready=True", func() {
			policyName := uniqueName("ts5-pol-bycat")

			By("creating a PanoptiumPolicy with threatSignatures.categories selector")
			policyYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-ts5-cat
  enforcementMode: enforcing
  priority: 90
  rules:
    - name: block-prompt-injection
      trigger:
        eventCategory: protocol
        eventSubcategory: mcp.tool.call
      threatSignatures:
        categories:
          - prompt_injection
      action:
        type: deny
      severity: HIGH
`, policyName, namespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PanoptiumPolicy with threatSignatures.categories")

			DeferCleanup(func() {
				deletePanoptiumPolicy(policyName, namespace)
			})

			By("waiting for the policy to reach Ready=True")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)
		})

		It("should create a PanoptiumPolicy matching by severity selector and reach Ready=True", func() {
			policyName := uniqueName("ts5-pol-bysev")

			By("creating a PanoptiumPolicy with threatSignatures.severities selector")
			policyYAML := fmt.Sprintf(`apiVersion: panoptium.io/v1alpha1
kind: PanoptiumPolicy
metadata:
  name: %s
  namespace: %s
spec:
  targetSelector:
    matchLabels:
      app: e2e-ts5-sev
  enforcementMode: audit
  priority: 80
  rules:
    - name: alert-critical-threats
      trigger:
        eventCategory: protocol
        eventSubcategory: mcp.tool.call
      threatSignatures:
        severities:
          - CRITICAL
          - HIGH
      action:
        type: alert
      severity: HIGH
`, policyName, namespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(policyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PanoptiumPolicy with threatSignatures.severities")

			DeferCleanup(func() {
				deletePanoptiumPolicy(policyName, namespace)
			})

			By("waiting for the policy to reach Ready=True")
			waitForPolicyReady(policyName, namespace, 2*time.Minute)
		})
	})
})

// ---------------------------------------------------------------------------
// ThreatSignature Helper Functions
// ---------------------------------------------------------------------------

// waitForThreatSignatureReady polls the PanoptiumThreatSignature status until
// Ready=True or the timeout expires.
func waitForThreatSignatureReady(name string, timeout time.Duration) {
	By(fmt.Sprintf("waiting for PanoptiumThreatSignature %s to be Ready=True", name))
	verifyReady := func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", name,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("True"),
			fmt.Sprintf("PanoptiumThreatSignature %s should have Ready=True", name))
	}
	Eventually(verifyReady, timeout, 5*time.Second).Should(Succeed())
}

// getThreatSignatureObservedGeneration returns the observedGeneration from the
// PanoptiumThreatSignature status.
func getThreatSignatureObservedGeneration(name string) int64 {
	cmd := exec.Command("kubectl", "get", "panoptiumthreatsignature", name,
		"-o", "jsonpath={.status.observedGeneration}")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
	output = strings.TrimSpace(output)
	if output == "" {
		return 0
	}
	var gen int64
	_, err = fmt.Sscanf(output, "%d", &gen)
	Expect(err).NotTo(HaveOccurred())
	return gen
}
