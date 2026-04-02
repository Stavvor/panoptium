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

package identity

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestRecordResolution_JWT verifies that JWT resolution increments the metric.
func TestRecordResolution_JWT(t *testing.T) {
	// Reset the counter for this test
	identityResolutionTotal.Reset()

	recordResolution("jwt", "success")

	metric := &dto.Metric{}
	counter, err := identityResolutionTotal.GetMetricWithLabelValues("jwt", "success")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues() error: %v", err)
	}

	if err := counter.(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	if got := metric.GetCounter().GetValue(); got != 1 {
		t.Errorf("counter value = %f, want 1", got)
	}
}

// TestRecordResolution_PodFallback verifies that pod fallback increments the metric.
func TestRecordResolution_PodFallback(t *testing.T) {
	identityResolutionTotal.Reset()

	recordResolution("pod", "fallback")

	metric := &dto.Metric{}
	counter, err := identityResolutionTotal.GetMetricWithLabelValues("pod", "fallback")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues() error: %v", err)
	}

	if err := counter.(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	if got := metric.GetCounter().GetValue(); got != 1 {
		t.Errorf("counter value = %f, want 1", got)
	}
}

// TestRecordResolution_IPUnknown verifies that IP unknown resolution increments the metric.
func TestRecordResolution_IPUnknown(t *testing.T) {
	identityResolutionTotal.Reset()

	recordResolution("ip", "unknown")

	metric := &dto.Metric{}
	counter, err := identityResolutionTotal.GetMetricWithLabelValues("ip", "unknown")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues() error: %v", err)
	}

	if err := counter.(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	if got := metric.GetCounter().GetValue(); got != 1 {
		t.Errorf("counter value = %f, want 1", got)
	}
}
