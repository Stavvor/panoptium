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
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// SamplerConfig configures the head sampler for backpressure handling.
type SamplerConfig struct {
	// Threshold is the number of events per window before sampling activates.
	// Default: 10000 events/sec.
	Threshold int64

	// SampleRate is the probability (0.0 to 1.0) of accepting an event
	// once the threshold is exceeded.
	SampleRate float64

	// Window is the time window for rate counting.
	// Default: 1 second.
	Window time.Duration
}

// HeadSampler implements probabilistic head sampling for backpressure control.
// When the event rate exceeds the configured threshold, it applies random
// sampling to shed load.
type HeadSampler struct {
	cfg           SamplerConfig
	mu            sync.Mutex
	count         int64
	windowStart   time.Time
	rng           *rand.Rand
	slowConsumers atomic.Int64
}

// NewHeadSampler creates a new HeadSampler with the given configuration.
func NewHeadSampler(cfg SamplerConfig) *HeadSampler {
	if cfg.Window == 0 {
		cfg.Window = time.Second
	}
	return &HeadSampler{
		cfg:         cfg,
		windowStart: time.Now(),
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Allow returns true if the event should be accepted, false if it should be dropped.
// Below the threshold, all events are accepted. Above the threshold, events are
// accepted with probability equal to the configured SampleRate.
func (s *HeadSampler) Allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Check if we need to reset the window
	if now.Sub(s.windowStart) > s.cfg.Window {
		s.count = 0
		s.windowStart = now
	}

	s.count++

	// Below threshold: always allow
	if s.count <= s.cfg.Threshold {
		return true
	}

	// Above threshold: probabilistic sampling
	return s.rng.Float64() < s.cfg.SampleRate
}

// RecordSlowConsumer increments the slow consumer advisory counter.
// This is called when NATS detects a slow consumer.
func (s *HeadSampler) RecordSlowConsumer() {
	s.slowConsumers.Add(1)
}

// SlowConsumerCount returns the total number of slow consumer advisories received.
func (s *HeadSampler) SlowConsumerCount() int64 {
	return s.slowConsumers.Load()
}
