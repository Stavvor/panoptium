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
	"fmt"
	"time"

	natsgo "github.com/nats-io/nats.go"
)

const (
	// Default retention periods per spec FR-5.
	defaultRetention            = 24 * time.Hour
	policyRetention             = 7 * 24 * time.Hour
	lifecycleRetention          = 30 * 24 * time.Hour
	highSeverityRetention       = 90 * 24 * time.Hour
	defaultMaxBytes       int64 = 1024 * 1024 * 1024 // 1GB
)

// StreamConfig holds configuration for JetStream stream provisioning.
type StreamConfig struct {
	// MaxBytesPerStream is the maximum size per stream in bytes.
	// Default: 1GB.
	MaxBytesPerStream int64

	// DefaultRetention is the retention period for standard event streams.
	// Default: 24 hours.
	DefaultRetention time.Duration

	// PolicyRetention is the retention period for policy.* event streams.
	// Default: 7 days.
	PolicyRetention time.Duration

	// LifecycleRetention is the retention period for lifecycle.* event streams.
	// Default: 30 days.
	LifecycleRetention time.Duration

	// HighSeverityRetention is the retention period for the high-severity stream.
	// Default: 90 days.
	HighSeverityRetention time.Duration
}

// DefaultStreamConfig returns a StreamConfig with spec-defined defaults.
func DefaultStreamConfig() StreamConfig {
	return StreamConfig{
		MaxBytesPerStream:     defaultMaxBytes,
		DefaultRetention:      defaultRetention,
		PolicyRetention:       policyRetention,
		LifecycleRetention:    lifecycleRetention,
		HighSeverityRetention: highSeverityRetention,
	}
}

// streamDef defines a single JetStream stream to provision.
type streamDef struct {
	Name     string
	Subjects []string
	MaxAge   time.Duration
}

// StreamManager provisions and manages JetStream streams for Panoptium events.
type StreamManager struct {
	js  natsgo.JetStreamContext
	cfg StreamConfig
}

// NewStreamManager creates a new StreamManager.
func NewStreamManager(js natsgo.JetStreamContext, cfg StreamConfig) *StreamManager {
	return &StreamManager{
		js:  js,
		cfg: cfg,
	}
}

// EnsureStreams creates all required JetStream streams if they do not already exist.
// This method is idempotent: calling it multiple times is safe.
func (m *StreamManager) EnsureStreams() error {
	streams := m.streamDefinitions()
	for _, sd := range streams {
		if err := m.ensureStream(sd); err != nil {
			return fmt.Errorf("ensuring stream %q: %w", sd.Name, err)
		}
	}
	return nil
}

// streamDefinitions returns the list of streams to provision based on the spec.
func (m *StreamManager) streamDefinitions() []streamDef {
	return []streamDef{
		{
			Name:     "PANOPTIUM_SYSCALL",
			Subjects: []string{"panoptium.events.*.syscall.>"},
			MaxAge:   m.cfg.DefaultRetention,
		},
		{
			Name:     "PANOPTIUM_NETWORK",
			Subjects: []string{"panoptium.events.*.network.>"},
			MaxAge:   m.cfg.DefaultRetention,
		},
		{
			Name:     "PANOPTIUM_PROTOCOL",
			Subjects: []string{"panoptium.events.*.protocol.>"},
			MaxAge:   m.cfg.DefaultRetention,
		},
		{
			Name:     "PANOPTIUM_LLM",
			Subjects: []string{"panoptium.events.*.llm.>"},
			MaxAge:   m.cfg.DefaultRetention,
		},
		{
			Name:     "PANOPTIUM_POLICY",
			Subjects: []string{"panoptium.events.*.policy.>"},
			MaxAge:   m.cfg.PolicyRetention,
		},
		{
			Name:     "PANOPTIUM_LIFECYCLE",
			Subjects: []string{"panoptium.events.*.lifecycle.>"},
			MaxAge:   m.cfg.LifecycleRetention,
		},
		{
			Name:     "PANOPTIUM_HIGH_SEVERITY",
			Subjects: []string{"panoptium.events.*.severity.high", "panoptium.events.*.severity.critical"},
			MaxAge:   m.cfg.HighSeverityRetention,
		},
	}
}

// ensureStream creates a stream if it does not exist, or verifies its configuration
// if it already exists.
func (m *StreamManager) ensureStream(sd streamDef) error {
	_, err := m.js.StreamInfo(sd.Name)
	if err == nil {
		// Stream already exists
		return nil
	}

	cfg := &natsgo.StreamConfig{
		Name:      sd.Name,
		Subjects:  sd.Subjects,
		Retention: natsgo.LimitsPolicy,
		MaxAge:    sd.MaxAge,
		MaxBytes:  m.cfg.MaxBytesPerStream,
		Discard:   natsgo.DiscardOld,
		Storage:   natsgo.FileStorage,
		Replicas:  1, // Embedded single-node
	}

	_, err = m.js.AddStream(cfg)
	if err != nil {
		return fmt.Errorf("adding stream: %w", err)
	}
	return nil
}
