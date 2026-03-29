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

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer/cgroup"
)

// mockInformer implements cgroup.PodInformer for testing.
type mockInformer struct {
	pods map[string]*cgroup.PodIdentity
}

func (m *mockInformer) GetPodByContainerID(containerID string) *cgroup.PodIdentity {
	return m.pods[containerID]
}

func newTestPublisher(t *testing.T) (*EventPublisher, eventbus.EventBus) {
	t.Helper()
	bus := eventbus.NewSimpleBus()

	informer := &mockInformer{
		pods: map[string]*cgroup.PodIdentity{
			"container-abc": {
				PodName:   "test-pod",
				Namespace: "default",
				Labels:    map[string]string{"app": "test"},
			},
		},
	}

	resolver := cgroup.NewCgroupResolver(informer)
	resolver.RegisterContainer(42, "container-abc")

	tracker := cgroup.NewProcessTreeTracker()

	publisher := NewEventPublisher(bus, resolver, tracker, WithWorkers(2))
	return publisher, bus
}

func serializeExecveEvent(t *testing.T, pid uint32, cgroupID uint64, filename string) []byte {
	t.Helper()
	evt := ExecveEvent{}
	evt.Header.Type = EventTypeExecve
	evt.Header.Timestamp = 1234567890
	evt.Header.PID = pid
	evt.Header.TGID = pid
	evt.Header.UID = 1000
	evt.Header.CgroupID = cgroupID
	copy(evt.Header.Comm[:], "test")
	copy(evt.Filename[:], filename)

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func serializeConnectEvent(t *testing.T, pid uint32, cgroupID uint64) []byte {
	t.Helper()
	evt := ConnectEvent{}
	evt.Header.Type = EventTypeConnect
	evt.Header.Timestamp = 1234567890
	evt.Header.PID = pid
	evt.Header.CgroupID = cgroupID
	evt.AddrFamily = 2 // AF_INET
	copy(evt.DstAddr[:4], []byte{10, 0, 0, 1})
	evt.DstPort = 8080

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &evt); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func TestNewEventPublisher(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	if publisher == nil {
		t.Fatal("expected non-nil publisher")
	}
}

func TestPublishExecveEvent(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	sub := bus.Subscribe("syscall.execve")
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	data := serializeExecveEvent(t, 100, 42, "/usr/bin/ls")
	publisher.PublishBatch([][]byte{data})

	select {
	case evt := <-sub.Events():
		if evt.EventType() != "syscall.execve" {
			t.Errorf("expected syscall.execve, got %s", evt.EventType())
		}
		if evt.Identity().PodName != "test-pod" {
			t.Errorf("expected test-pod, got %q", evt.Identity().PodName)
		}
		if evt.Identity().Namespace != "default" {
			t.Errorf("expected default, got %q", evt.Identity().Namespace)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestPublishConnectEvent(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	sub := bus.Subscribe("syscall.connect")
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	data := serializeConnectEvent(t, 200, 42)
	publisher.PublishBatch([][]byte{data})

	select {
	case evt := <-sub.Events():
		if evt.EventType() != "syscall.connect" {
			t.Errorf("expected syscall.connect, got %s", evt.EventType())
		}
		if evt.Identity().PodName != "test-pod" {
			t.Errorf("expected test-pod, got %q", evt.Identity().PodName)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestPublishBatchMultipleEvents(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	sub := bus.Subscribe()
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	batch := [][]byte{
		serializeExecveEvent(t, 100, 42, "/bin/bash"),
		serializeConnectEvent(t, 200, 42),
	}
	publisher.PublishBatch(batch)

	received := 0
	timeout := time.After(2 * time.Second)
	for received < 2 {
		select {
		case <-sub.Events():
			received++
		case <-timeout:
			t.Fatalf("timeout: received %d of 2 events", received)
		}
	}
}

func TestPublishUnknownCgroup(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	sub := bus.Subscribe("syscall.execve")
	defer bus.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	// Use unknown cgroup ID.
	data := serializeExecveEvent(t, 300, 9999, "/usr/bin/unknown")
	publisher.PublishBatch([][]byte{data})

	select {
	case evt := <-sub.Events():
		// Event should still be published, just without pod identity.
		if evt.Identity().PodName != "" {
			t.Errorf("expected empty pod name for unknown cgroup, got %q", evt.Identity().PodName)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestPublishInvalidData(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	// Publish invalid data.
	publisher.PublishBatch([][]byte{{0x00}})

	// Wait briefly for processing.
	time.Sleep(100 * time.Millisecond)

	if publisher.metrics.EnrichErrors.Load() == 0 {
		t.Error("expected enrich error for invalid data")
	}
}

func TestPublisherStop(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	publisher.Stop()

	// Double stop should be safe.
	publisher.Stop()
}

func TestPublisherMetrics(t *testing.T) {
	publisher, bus := newTestPublisher(t)
	defer bus.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	data := serializeExecveEvent(t, 100, 42, "/usr/bin/ls")
	publisher.PublishBatch([][]byte{data})

	time.Sleep(200 * time.Millisecond)

	metrics := publisher.Metrics()
	if metrics.EventsPublished.Load() < 1 {
		t.Error("expected at least 1 published event")
	}
	if metrics.EventsProcessed.Load() < 1 {
		t.Error("expected at least 1 processed event")
	}
}

func TestPublisherForkUpdatesTracker(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	tracker := cgroup.NewProcessTreeTracker()
	publisher := NewEventPublisher(bus, nil, tracker, WithWorkers(1))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publisher.Start(ctx)
	defer publisher.Stop()

	// Create a fork event.
	forkEvt := ForkEvent{}
	forkEvt.Header.Type = EventTypeFork
	forkEvt.Header.Timestamp = 1234567890
	forkEvt.Header.PID = 100
	forkEvt.ParentPID = 100
	forkEvt.ChildPID = 200

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &forkEvt); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	publisher.PublishBatch([][]byte{buf.Bytes()})
	time.Sleep(200 * time.Millisecond)

	// Verify the tracker was updated.
	parent := tracker.GetParent(200)
	if parent != 100 {
		t.Errorf("expected parent 100, got %d", parent)
	}
}
