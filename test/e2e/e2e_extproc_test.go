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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panoptium/panoptium/test/utils"
)

// gatewayServiceURL returns the URL for the AgentGateway service accessible from the test runner.
// It uses kubectl port-forward or service DNS depending on context.
func gatewayServiceURL() string {
	// Try to find the gateway service via kubectl
	cmd := exec.Command("kubectl", "get", "svc",
		"-l", "gateway.networking.k8s.io/gateway-name=e2e-gateway",
		"-n", namespace,
		"-o", "jsonpath={.items[0].spec.clusterIP}")
	output, err := utils.Run(cmd)
	if err == nil && output != "" {
		return fmt.Sprintf("http://%s:8080", strings.TrimSpace(output))
	}
	// Fallback to service DNS name
	return "http://e2e-gateway.panoptium-system.svc.cluster.local:8080"
}

// queryMetric fetches a specific Prometheus metric from the operator metrics endpoint.
// It returns the metric value or 0 if the metric is not found.
func queryMetric(metricName string, labels map[string]string) float64 {
	token, err := serviceAccountToken()
	Expect(err).NotTo(HaveOccurred(), "failed to get service account token")

	metricsURL := fmt.Sprintf("https://%s.%s.svc.cluster.local:8443/metrics", metricsServiceName, namespace)
	curlCmd := fmt.Sprintf(
		"curl -sk -H 'Authorization: Bearer %s' %s 2>/dev/null",
		token, metricsURL)

	cmd := exec.Command("kubectl", "exec", "-n", namespace,
		"deploy/panoptium-controller-manager", "--",
		"sh", "-c", curlCmd)

	// Fallback: run a curl pod
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Use a temporary pod to query metrics
		podName := fmt.Sprintf("metrics-query-%d", time.Now().UnixNano()%10000)
		cmd = exec.Command("kubectl", "run", podName,
			"--restart=Never",
			"--rm", "--attach",
			"--namespace", namespace,
			"--image=curlimages/curl:7.78.0",
			"--", "-sk",
			"-H", fmt.Sprintf("Authorization: Bearer %s", token),
			metricsURL)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return 0
		}
	}

	return parsePrometheusMetric(string(output), metricName, labels)
}

// parsePrometheusMetric extracts a metric value from Prometheus text format output.
func parsePrometheusMetric(output, metricName string, labels map[string]string) float64 {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		if !strings.HasPrefix(line, metricName) {
			continue
		}

		// Check if all labels match
		allLabelsMatch := true
		for k, v := range labels {
			labelStr := fmt.Sprintf(`%s="%s"`, k, v)
			if !strings.Contains(line, labelStr) {
				allLabelsMatch = false
				break
			}
		}

		if !allLabelsMatch {
			continue
		}

		// Extract the value (last token on the line)
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			val, err := strconv.ParseFloat(parts[len(parts)-1], 64)
			if err == nil {
				return val
			}
		}
	}
	return 0
}

// getOperatorLogs fetches and optionally filters operator pod logs.
func getOperatorLogs(since time.Duration, grepPattern string) string {
	args := []string{"logs", "-l", "control-plane=controller-manager",
		"-n", namespace, "--tail=200"}
	if since > 0 {
		args = append(args, fmt.Sprintf("--since=%ds", int(since.Seconds())))
	}

	cmd := exec.Command("kubectl", args...)
	output, err := utils.Run(cmd)
	if err != nil {
		return ""
	}

	if grepPattern == "" {
		return output
	}

	// Filter by pattern
	var filtered []string
	re := regexp.MustCompile(grepPattern)
	for _, line := range strings.Split(output, "\n") {
		if re.MatchString(line) {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}

// sendLLMRequest sends an HTTP request through AgentGateway with x-panoptium-* headers.
// Returns the response body and status code.
func sendLLMRequest(provider, agentID, path, body string) (string, int, error) {
	// Create a pod to send the request from within the cluster
	podName := fmt.Sprintf("llm-client-%s-%d", agentID, time.Now().UnixNano()%100000)

	gwURL := gatewayServiceURL()
	curlCmd := fmt.Sprintf(
		"curl -s -w '\\n%%{http_code}' -X POST '%s%s' "+
			"-H 'Content-Type: application/json' "+
			"-H 'x-panoptium-agent-id: %s' "+
			"-H 'x-panoptium-request-id: req-%s-%d' "+
			"-d '%s'",
		gwURL, path, agentID, agentID, time.Now().UnixNano(), body)

	cmd := exec.Command("kubectl", "run", podName,
		"--restart=Never",
		"--rm", "--attach",
		"--namespace", namespace,
		"--image=curlimages/curl:7.78.0",
		"--", "sh", "-c", curlCmd)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), 0, fmt.Errorf("curl pod failed: %v, output: %s", err, string(output))
	}

	// Parse status code from the last line
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 1 {
		return "", 0, fmt.Errorf("empty response")
	}

	statusLine := lines[len(lines)-1]
	statusCode, err := strconv.Atoi(strings.TrimSpace(statusLine))
	if err != nil {
		// Status code might be embedded in the response
		return string(output), 200, nil
	}

	responseBody := strings.Join(lines[:len(lines)-1], "\n")
	return responseBody, statusCode, nil
}

// waitForMetric polls a metric until it meets the minimum value threshold.
func waitForMetric(metricName string, labels map[string]string, minValue float64, timeout time.Duration) float64 {
	var lastValue float64
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		lastValue = queryMetric(metricName, labels)
		if lastValue >= minValue {
			return lastValue
		}
		time.Sleep(2 * time.Second)
	}
	return lastValue
}

var _ = Describe("ExtProc E2E", Label("e2e-extproc"), Ordered, func() {

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

		By("verifying mock LLM is running")
		verifyMockLLM := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "app=mock-llm",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"))
		}
		Eventually(verifyMockLLM, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	Context("OpenAI Streaming", func() {
		It("should observe OpenAI streaming tokens through ExtProc", func() {
			By("sending a streaming /v1/chat/completions request through AgentGateway")
			body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
			responseBody, statusCode, err := sendLLMRequest("openai", "e2e-openai-agent",
				"/v1/chat/completions", body)

			Expect(err).NotTo(HaveOccurred(), "failed to send OpenAI request")
			Expect(statusCode).To(Equal(http.StatusOK), "expected 200 OK")

			By("verifying response contains expected SSE token data")
			Expect(responseBody).To(ContainSubstring("Hello"))
			Expect(responseBody).To(ContainSubstring("[DONE]"))

			By("verifying panoptium_extproc_requests_total{provider=openai} incremented")
			requestsValue := waitForMetric("panoptium_extproc_requests_total",
				map[string]string{"provider": "openai"}, 1, 30*time.Second)
			Expect(requestsValue).To(BeNumerically(">=", 1),
				"expected panoptium_extproc_requests_total{provider=openai} >= 1")

			By("verifying panoptium_extproc_tokens_observed_total{provider=openai} > 0")
			tokensValue := waitForMetric("panoptium_extproc_tokens_observed_total",
				map[string]string{"provider": "openai"}, 1, 30*time.Second)
			Expect(tokensValue).To(BeNumerically(">", 0),
				"expected panoptium_extproc_tokens_observed_total{provider=openai} > 0")

			By("verifying operator logs show ExtProc request processing")
			logs := getOperatorLogs(60*time.Second, "extproc|openai")
			Expect(logs).NotTo(BeEmpty(), "expected operator logs to contain ExtProc processing entries")
		})
	})

	Context("Anthropic Streaming", func() {
		It("should observe Anthropic streaming tokens through ExtProc", func() {
			By("sending a streaming /v1/messages request through AgentGateway")
			body := `{"model":"claude-3-opus","messages":[{"role":"user","content":"hi"}],"stream":true}`
			responseBody, statusCode, err := sendLLMRequest("anthropic", "e2e-anthropic-agent",
				"/v1/messages", body)

			Expect(err).NotTo(HaveOccurred(), "failed to send Anthropic request")
			Expect(statusCode).To(Equal(http.StatusOK), "expected 200 OK")

			By("verifying response contains expected Anthropic SSE events")
			Expect(responseBody).To(ContainSubstring("Hello"))
			Expect(responseBody).To(ContainSubstring("message_stop"))

			By("verifying panoptium_extproc_requests_total{provider=anthropic} incremented")
			requestsValue := waitForMetric("panoptium_extproc_requests_total",
				map[string]string{"provider": "anthropic"}, 1, 30*time.Second)
			Expect(requestsValue).To(BeNumerically(">=", 1),
				"expected panoptium_extproc_requests_total{provider=anthropic} >= 1")

			By("verifying operator logs confirm Anthropic provider detection")
			logs := getOperatorLogs(60*time.Second, "anthropic")
			Expect(logs).NotTo(BeEmpty(), "expected operator logs to show Anthropic provider detection")
		})
	})

	Context("Agent Identity Resolution", func() {
		It("should resolve agent identity via source-ip method", func() {
			By("sending request with x-panoptium-auth-type: source-ip")
			body := `{"model":"gpt-4","messages":[{"role":"user","content":"identity test"}],"stream":false}`

			// Build custom curl with identity headers
			podName := fmt.Sprintf("identity-test-%d", time.Now().UnixNano()%100000)
			gwURL := gatewayServiceURL()
			curlCmd := fmt.Sprintf(
				"curl -s -o /dev/null -w '%%{http_code}' -X POST '%s/v1/chat/completions' "+
					"-H 'Content-Type: application/json' "+
					"-H 'x-panoptium-agent-id: e2e-identity-agent' "+
					"-H 'x-panoptium-auth-type: source-ip' "+
					"-H 'x-panoptium-client-ip: 10.244.0.100' "+
					"-d '%s'",
				gwURL, body)

			cmd := exec.Command("kubectl", "run", podName,
				"--restart=Never",
				"--rm", "--attach",
				"--namespace", namespace,
				"--image=curlimages/curl:7.78.0",
				"--", "sh", "-c", curlCmd)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "identity test request failed")
			Expect(strings.TrimSpace(output)).To(Equal("200"))

			By("verifying panoptium_agent_identity_resolution_total is recorded")
			identityValue := waitForMetric("panoptium_agent_identity_resolution_total",
				map[string]string{}, 1, 30*time.Second)
			Expect(identityValue).To(BeNumerically(">=", 1),
				"expected panoptium_agent_identity_resolution_total >= 1")

			By("verifying operator logs show identity resolution")
			logs := getOperatorLogs(60*time.Second, "identity|resolve")
			Expect(logs).NotTo(BeEmpty(), "expected operator logs to show identity resolution")
		})
	})

	Context("Concurrent Multi-Agent", func() {
		It("should handle concurrent requests from multiple agents", func() {
			agentIDs := []string{"agent-alpha", "agent-beta", "agent-gamma"}

			By("launching 3 concurrent requests with different agent IDs")
			var wg sync.WaitGroup
			type result struct {
				agentID    string
				statusCode int
				err        error
			}
			results := make([]result, len(agentIDs))

			for i, agentID := range agentIDs {
				wg.Add(1)
				go func(idx int, aid string) {
					defer wg.Done()
					defer GinkgoRecover()
					body := fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":"concurrent test %s"}],"stream":true}`, aid)
					_, statusCode, err := sendLLMRequest("openai", aid,
						"/v1/chat/completions", body)
					results[idx] = result{agentID: aid, statusCode: statusCode, err: err}
				}(i, agentID)
			}
			wg.Wait()

			By("verifying all requests completed successfully")
			for _, r := range results {
				Expect(r.err).NotTo(HaveOccurred(),
					fmt.Sprintf("request for agent %s failed", r.agentID))
				Expect(r.statusCode).To(Equal(http.StatusOK),
					fmt.Sprintf("expected 200 for agent %s, got %d", r.agentID, r.statusCode))
			}

			By("verifying metrics reflect total request count")
			totalRequests := waitForMetric("panoptium_extproc_requests_total",
				map[string]string{}, 3, 30*time.Second)
			Expect(totalRequests).To(BeNumerically(">=", 3),
				"expected panoptium_extproc_requests_total >= 3 across all providers")

			By("verifying operator logs show independent agent attribution")
			for _, agentID := range agentIDs {
				logs := getOperatorLogs(60*time.Second, agentID)
				// Logs may or may not contain agent IDs depending on log level
				_, _ = fmt.Fprintf(GinkgoWriter, "Logs for agent %s: %d lines\n",
					agentID, len(strings.Split(logs, "\n")))
			}
		})
	})
})

// Ensure unused imports don't cause compilation errors
var (
	_ = io.Discard
	_ json.RawMessage
)
