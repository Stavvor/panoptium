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

package extproc

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// getGaugeValue reads the current value of a prometheus.Gauge.
func getGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := gauge.Write(metric); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	return metric.GetGauge().GetValue()
}

// getCounterValue reads the current value of a prometheus.Counter.
func getCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := counter.(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	return metric.GetCounter().GetValue()
}

// TestRecordStreamStartAndEnd verifies that active streams gauge increments
// on start and decrements on end.
func TestRecordStreamStartAndEnd(t *testing.T) {
	// Reset gauge to zero
	activeStreams.Set(0)

	RecordStreamStart()
	if got := getGaugeValue(t, activeStreams); got != 1 {
		t.Errorf("after RecordStreamStart(), active_streams = %f, want 1", got)
	}

	RecordStreamStart()
	if got := getGaugeValue(t, activeStreams); got != 2 {
		t.Errorf("after second RecordStreamStart(), active_streams = %f, want 2", got)
	}

	RecordStreamEnd()
	if got := getGaugeValue(t, activeStreams); got != 1 {
		t.Errorf("after RecordStreamEnd(), active_streams = %f, want 1", got)
	}

	RecordStreamEnd()
	if got := getGaugeValue(t, activeStreams); got != 0 {
		t.Errorf("after second RecordStreamEnd(), active_streams = %f, want 0", got)
	}
}

// TestRecordRequest verifies that requests_total counter increments per provider.
func TestRecordRequest(t *testing.T) {
	requestsTotal.Reset()

	RecordRequest("openai")
	RecordRequest("openai")
	RecordRequest("anthropic")

	openaiCounter, err := requestsTotal.GetMetricWithLabelValues("openai")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(openai) error: %v", err)
	}
	if got := getCounterValue(t, openaiCounter); got != 2 {
		t.Errorf("openai requests_total = %f, want 2", got)
	}

	anthropicCounter, err := requestsTotal.GetMetricWithLabelValues("anthropic")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(anthropic) error: %v", err)
	}
	if got := getCounterValue(t, anthropicCounter); got != 1 {
		t.Errorf("anthropic requests_total = %f, want 1", got)
	}
}

// TestRecordTokensObserved verifies that tokens_observed_total increments
// correctly with batch counts.
func TestRecordTokensObserved(t *testing.T) {
	tokensObservedTotal.Reset()

	RecordTokensObserved("openai", 5)
	RecordTokensObserved("openai", 3)
	RecordTokensObserved("anthropic", 10)

	openaiCounter, err := tokensObservedTotal.GetMetricWithLabelValues("openai")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(openai) error: %v", err)
	}
	if got := getCounterValue(t, openaiCounter); got != 8 {
		t.Errorf("openai tokens_observed_total = %f, want 8", got)
	}

	anthropicCounter, err := tokensObservedTotal.GetMetricWithLabelValues("anthropic")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(anthropic) error: %v", err)
	}
	if got := getCounterValue(t, anthropicCounter); got != 10 {
		t.Errorf("anthropic tokens_observed_total = %f, want 10", got)
	}
}

// TestRecordParseError verifies that parse_errors_total increments
// per provider and phase.
func TestRecordParseError(t *testing.T) {
	parseErrorsTotal.Reset()

	RecordParseError("openai", "request")
	RecordParseError("openai", "response")
	RecordParseError("openai", "response")
	RecordParseError("anthropic", "response")

	tests := []struct {
		provider string
		phase    string
		want     float64
	}{
		{"openai", "request", 1},
		{"openai", "response", 2},
		{"anthropic", "response", 1},
	}

	for _, tt := range tests {
		counter, err := parseErrorsTotal.GetMetricWithLabelValues(tt.provider, tt.phase)
		if err != nil {
			t.Fatalf("GetMetricWithLabelValues(%s, %s) error: %v", tt.provider, tt.phase, err)
		}
		if got := getCounterValue(t, counter); got != tt.want {
			t.Errorf("%s/%s parse_errors_total = %f, want %f", tt.provider, tt.phase, got, tt.want)
		}
	}
}

// TestMetricsRegistered verifies that all ExtProc metrics are properly
// initialized and accessible.
func TestMetricsRegistered(t *testing.T) {
	// Verify each metric variable is non-nil (properly initialized)
	if activeStreams == nil {
		t.Error("activeStreams metric is nil")
	}
	if requestsTotal == nil {
		t.Error("requestsTotal metric is nil")
	}
	if tokensObservedTotal == nil {
		t.Error("tokensObservedTotal metric is nil")
	}
	if parseErrorsTotal == nil {
		t.Error("parseErrorsTotal metric is nil")
	}
}
