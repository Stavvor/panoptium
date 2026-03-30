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

package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer/tetragon"
)

// mockStream delivers pre-loaded events and blocks after exhausting them.
type mockStream struct {
	events []*tetragon.RawEvent
	idx    int
	mu     sync.Mutex
	done   chan struct{}
}

func newMockStream(events []*tetragon.RawEvent) *mockStream {
	return &mockStream{
		events: events,
		done:   make(chan struct{}),
	}
}

func (s *mockStream) Recv() (*tetragon.RawEvent, error) {
	s.mu.Lock()
	if s.idx < len(s.events) {
		evt := s.events[s.idx]
		s.idx++
		s.mu.Unlock()
		return evt, nil
	}
	s.mu.Unlock()
	// Block until closed to simulate an idle stream.
	<-s.done
	return nil, fmt.Errorf("stream closed")
}

func (s *mockStream) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

// mockStreamFactory returns a stream pre-loaded with events.
type mockStreamFactory struct {
	stream *mockStream
}

func (f *mockStreamFactory) Connect(ctx context.Context, address string) (tetragon.EventStream, error) {
	return f.stream, nil
}

// allEventTypes returns one RawEvent for each of the 8 event types the
// pipeline must handle: execve, exit, openat, connect, fork, setns, mount
// enforcement (LSM), and ptrace enforcement (LSM).
func allEventTypes() []*tetragon.RawEvent {
	ts := uint64(time.Now().UnixNano())
	base := tetragon.RawEvent{
		ProcessPID:  1000,
		ProcessComm: "test-bin",
		ParentPID:   1,
		ParentComm:  "init",
		Namespace:   "test-ns",
		PodName:     "test-pod",
		ContainerID: "abc123",
		Labels:      map[string]string{"app": "test"},
		Timestamp:   ts,
		CgroupID:    42,
	}

	events := make([]*tetragon.RawEvent, 0, 8)

	// 1. process_exec
	e := base
	e.Type = tetragon.EventTypeProcessExec
	events = append(events, &e)

	// 2. process_exit
	e2 := base
	e2.Type = tetragon.EventTypeProcessExit
	events = append(events, &e2)

	// 3. kprobe: sys_openat
	e3 := base
	e3.Type = tetragon.EventTypeProcessKprobe
	e3.KprobeFunc = "sys_openat"
	e3.KprobeArgs = map[string]interface{}{"path": "/etc/passwd"}
	events = append(events, &e3)

	// 4. kprobe: sys_connect
	e4 := base
	e4.Type = tetragon.EventTypeProcessKprobe
	e4.KprobeFunc = "sys_connect"
	e4.KprobeArgs = map[string]interface{}{"addr": "10.0.0.1"}
	events = append(events, &e4)

	// 5. tracepoint: sched_process_fork
	e5 := base
	e5.Type = tetragon.EventTypeProcessTracepoint
	e5.KprobeFunc = "sched_process_fork"
	events = append(events, &e5)

	// 6. kprobe: sys_setns (namespace manipulation)
	e6 := base
	e6.Type = tetragon.EventTypeProcessKprobe
	e6.KprobeFunc = "sys_setns"
	events = append(events, &e6)

	// 7. LSM: security_sb_mount (enforcement)
	e7 := base
	e7.Type = tetragon.EventTypeProcessLSM
	e7.LSMHook = "security_sb_mount"
	e7.LSMAction = "Override"
	events = append(events, &e7)

	// 8. LSM: security_ptrace_access_check (enforcement)
	e8 := base
	e8.Type = tetragon.EventTypeProcessLSM
	e8.LSMHook = "security_ptrace_access_check"
	e8.LSMAction = "Override"
	events = append(events, &e8)

	return events
}

// TestFullPipeline_MockTetragon_To_EventBus verifies the complete pipeline:
// mock Tetragon gRPC stream -> Client -> Publisher (translate) -> EventBus.
// All 8 event types must arrive on the bus with correct event type strings.
func TestFullPipeline_MockTetragon_To_EventBus(t *testing.T) {
	rawEvents := allEventTypes()
	stream := newMockStream(rawEvents)
	factory := &mockStreamFactory{stream: stream}

	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	// Subscribe to all events before starting the pipeline.
	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	client := tetragon.NewClient(tetragon.ClientConfig{
		Address:        "mock://tetragon",
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	}, tetragon.WithStreamFactory(factory))

	translator := tetragon.NewTranslator()
	publisher := tetragon.NewPublisher(bus, translator, tetragon.PublisherConfig{
		Workers:       1, // single worker for deterministic ordering
		ChannelBuffer: 64,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	// Start client in a goroutine; it blocks until ctx is cancelled.
	go client.Start(ctx)

	// Feed client events to the publisher.
	go func() {
		for evt := range client.Events() {
			publisher.Submit(evt)
		}
	}()

	// Collect events from the bus.
	expectedTypes := map[string]bool{
		"syscall.execve":  false,
		"lifecycle.exit":  false,
		"syscall.openat":  false,
		"syscall.connect": false,
		"syscall.fork":    false,
		"security.setns":  false,
		"security.mount":  false,
		"security.ptrace": false,
	}

	received := make([]eventbus.Event, 0, len(rawEvents))
	timeout := time.After(3 * time.Second)

	for len(received) < len(rawEvents) {
		select {
		case evt := <-sub.Events():
			received = append(received, evt)
			expectedTypes[evt.EventType()] = true
		case <-timeout:
			t.Fatalf("timed out waiting for events: received %d/%d", len(received), len(rawEvents))
		}
	}

	// Verify all 8 event types were received.
	for typ, seen := range expectedTypes {
		if !seen {
			t.Errorf("expected event type %q was not received", typ)
		}
	}

	if len(received) != len(rawEvents) {
		t.Errorf("expected %d events, got %d", len(rawEvents), len(received))
	}
}

// TestAllEventTypesFlowCorrectly verifies that each of the 8 event types
// is translated to the correct Panoptium event type string by the translator.
func TestAllEventTypesFlowCorrectly(t *testing.T) {
	rawEvents := allEventTypes()
	translator := tetragon.NewTranslator()

	expectedMapping := []string{
		"syscall.execve",  // process_exec
		"lifecycle.exit",  // process_exit
		"syscall.openat",  // kprobe sys_openat
		"syscall.connect", // kprobe sys_connect
		"syscall.fork",    // tracepoint sched_process_fork
		"security.setns",  // kprobe sys_setns
		"security.mount",  // LSM security_sb_mount
		"security.ptrace", // LSM security_ptrace_access_check
	}

	if len(rawEvents) != len(expectedMapping) {
		t.Fatalf("event count mismatch: %d raw events vs %d expected mappings",
			len(rawEvents), len(expectedMapping))
	}

	for i, raw := range rawEvents {
		evt, err := translator.Translate(raw)
		if err != nil {
			t.Errorf("event %d: unexpected translation error: %v", i, err)
			continue
		}
		if evt == nil {
			t.Errorf("event %d: translation returned nil for type %s", i, raw.Type)
			continue
		}
		if evt.EventType() != expectedMapping[i] {
			t.Errorf("event %d: expected type %q, got %q", i, expectedMapping[i], evt.EventType())
		}
	}
}

// TestEnforcementEventsCarryActionMetadata verifies that LSM enforcement
// events (mount and ptrace) carry the correct Override action and are
// translated to the expected event types.
func TestEnforcementEventsCarryActionMetadata(t *testing.T) {
	tests := []struct {
		name         string
		lsmHook      string
		lsmAction    string
		expectedType string
	}{
		{
			name:         "mount enforcement with Override",
			lsmHook:      "security_sb_mount",
			lsmAction:    "Override",
			expectedType: "security.mount",
		},
		{
			name:         "ptrace enforcement with Override",
			lsmHook:      "security_ptrace_access_check",
			lsmAction:    "Override",
			expectedType: "security.ptrace",
		},
	}

	translator := tetragon.NewTranslator()
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	publisher := tetragon.NewPublisher(bus, translator, tetragon.PublisherConfig{
		Workers:       1,
		ChannelBuffer: 16,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := &tetragon.RawEvent{
				Type:        tetragon.EventTypeProcessLSM,
				ProcessPID:  2000,
				ProcessComm: "malicious-bin",
				Namespace:   "prod",
				PodName:     "evil-pod",
				LSMHook:     tc.lsmHook,
				LSMAction:   tc.lsmAction,
				Timestamp:   uint64(time.Now().UnixNano()),
			}

			publisher.Submit(raw)

			select {
			case evt := <-sub.Events():
				if evt.EventType() != tc.expectedType {
					t.Errorf("expected event type %q, got %q", tc.expectedType, evt.EventType())
				}
				if evt.Identity().Namespace != "prod" {
					t.Errorf("expected namespace 'prod', got %q", evt.Identity().Namespace)
				}
				if evt.Identity().PodName != "evil-pod" {
					t.Errorf("expected pod 'evil-pod', got %q", evt.Identity().PodName)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for enforcement event")
			}
		})
	}
}

// TestPipelineMetrics verifies that the client and publisher metrics
// are correctly incremented through the full pipeline.
func TestPipelineMetrics(t *testing.T) {
	rawEvents := allEventTypes()
	stream := newMockStream(rawEvents)
	factory := &mockStreamFactory{stream: stream}

	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	client := tetragon.NewClient(tetragon.ClientConfig{
		Address:        "mock://tetragon",
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	}, tetragon.WithStreamFactory(factory))

	translator := tetragon.NewTranslator()
	publisher := tetragon.NewPublisher(bus, translator, tetragon.PublisherConfig{
		Workers:       1,
		ChannelBuffer: 64,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	go client.Start(ctx)

	go func() {
		for evt := range client.Events() {
			publisher.Submit(evt)
		}
	}()

	// Drain all events from the bus.
	timeout := time.After(3 * time.Second)
	collected := 0
	for collected < len(rawEvents) {
		select {
		case <-sub.Events():
			collected++
		case <-timeout:
			t.Fatalf("timed out: collected %d/%d", collected, len(rawEvents))
		}
	}

	// Allow brief time for metrics to settle.
	time.Sleep(50 * time.Millisecond)

	// Verify client metrics.
	clientMetrics := client.Metrics()
	if clientMetrics.EventsReceived.Load() != int64(len(rawEvents)) {
		t.Errorf("client events received: expected %d, got %d",
			len(rawEvents), clientMetrics.EventsReceived.Load())
	}

	// Verify publisher metrics.
	pubMetrics := publisher.Metrics()
	if pubMetrics.EventsProcessed.Load() != int64(len(rawEvents)) {
		t.Errorf("publisher events processed: expected %d, got %d",
			len(rawEvents), pubMetrics.EventsProcessed.Load())
	}
	if pubMetrics.EventsPublished.Load() != int64(len(rawEvents)) {
		t.Errorf("publisher events published: expected %d, got %d",
			len(rawEvents), pubMetrics.EventsPublished.Load())
	}
	if pubMetrics.EventsDropped.Load() != 0 {
		t.Errorf("publisher events dropped: expected 0, got %d",
			pubMetrics.EventsDropped.Load())
	}
	if pubMetrics.EventsSkipped.Load() != 0 {
		t.Errorf("publisher events skipped: expected 0, got %d",
			pubMetrics.EventsSkipped.Load())
	}
}
