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

package nats

import (
	"testing"
	"time"
)

// TestHeadSampler_AllowsBelowThreshold verifies all events pass below threshold.
func TestHeadSampler_AllowsBelowThreshold(t *testing.T) {
	s := NewHeadSampler(SamplerConfig{
		Threshold:  10000,
		SampleRate: 0.1,
	})

	// Below threshold: all should be allowed
	allowed := 0
	for i := 0; i < 100; i++ {
		if s.Allow() {
			allowed++
		}
	}

	if allowed != 100 {
		t.Errorf("Expected all 100 events allowed below threshold, got %d", allowed)
	}
}

// TestHeadSampler_SamplesAboveThreshold verifies sampling activates above threshold.
func TestHeadSampler_SamplesAboveThreshold(t *testing.T) {
	s := NewHeadSampler(SamplerConfig{
		Threshold:  100, // Low threshold for testing
		SampleRate: 0.5, // 50% sampling
	})

	// Exhaust the threshold
	for i := 0; i < 100; i++ {
		s.Allow()
	}

	// Now sampling should be active
	allowed := 0
	total := 10000
	for i := 0; i < total; i++ {
		if s.Allow() {
			allowed++
		}
	}

	// With 50% sampling, expect roughly 5000 +/- 500
	expectedMin := 4000
	expectedMax := 6000
	if allowed < expectedMin || allowed > expectedMax {
		t.Errorf("Expected %d-%d allowed events with 50%% sampling, got %d", expectedMin, expectedMax, allowed)
	}
}

// TestHeadSampler_ConfigurableRate verifies sampling rate is configurable.
func TestHeadSampler_ConfigurableRate(t *testing.T) {
	s := NewHeadSampler(SamplerConfig{
		Threshold:  1,   // Immediately start sampling
		SampleRate: 0.1, // 10% sampling
	})

	// Exhaust threshold
	s.Allow()

	allowed := 0
	total := 10000
	for i := 0; i < total; i++ {
		if s.Allow() {
			allowed++
		}
	}

	// With 10% sampling, expect roughly 1000 +/- 300
	expectedMin := 500
	expectedMax := 1500
	if allowed < expectedMin || allowed > expectedMax {
		t.Errorf("Expected %d-%d allowed events with 10%% sampling, got %d", expectedMin, expectedMax, allowed)
	}
}

// TestHeadSampler_ResetsAfterWindow verifies the sampler resets after the time window.
func TestHeadSampler_ResetsAfterWindow(t *testing.T) {
	s := NewHeadSampler(SamplerConfig{
		Threshold:  10,
		SampleRate: 0.0, // 0% sampling = drop everything above threshold
		Window:     100 * time.Millisecond,
	})

	// Exhaust threshold
	for i := 0; i < 10; i++ {
		s.Allow()
	}

	// Above threshold with 0% rate: should be dropped
	if s.Allow() {
		t.Error("Expected event to be dropped above threshold with 0% rate")
	}

	// Wait for window to reset
	time.Sleep(150 * time.Millisecond)

	// After reset, should be allowed again
	if !s.Allow() {
		t.Error("Expected event to be allowed after window reset")
	}
}

// TestHeadSampler_SlowConsumerMetric verifies slow consumer advisory triggers metric.
func TestHeadSampler_SlowConsumerMetric(t *testing.T) {
	s := NewHeadSampler(SamplerConfig{
		Threshold:  10000,
		SampleRate: 0.1,
	})

	// Record slow consumer events
	s.RecordSlowConsumer()
	s.RecordSlowConsumer()

	count := s.SlowConsumerCount()
	if count != 2 {
		t.Errorf("SlowConsumerCount = %d, want 2", count)
	}
}
