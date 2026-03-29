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
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer/cgroup"
)

const (
	// defaultWorkers is the default worker pool size for event processing.
	defaultWorkers = 4

	// eventChannelBuffer is the size of the internal event processing channel.
	eventChannelBuffer = 256
)

// PublisherMetrics tracks event publishing performance counters.
type PublisherMetrics struct {
	EventsPublished  atomic.Int64
	EnrichErrors     atomic.Int64
	PublishErrors    atomic.Int64
	EventsProcessed  atomic.Int64
}

// EventPublisher reads raw eBPF events, enriches them with pod identity,
// and publishes them to the event bus as PanoptiumEvents.
type EventPublisher struct {
	mu sync.Mutex

	bus      eventbus.EventBus
	resolver *cgroup.CgroupResolver
	tracker  *cgroup.ProcessTreeTracker

	workers int
	closed  bool

	metrics PublisherMetrics

	// events channel for worker pool processing.
	events chan rawEvent
	wg     sync.WaitGroup
}

// rawEvent pairs raw bytes with their parsed event type.
type rawEvent struct {
	data []byte
}

// PublisherOption configures the EventPublisher.
type PublisherOption func(*EventPublisher)

// WithWorkers sets the number of worker goroutines for event processing.
func WithWorkers(n int) PublisherOption {
	return func(p *EventPublisher) {
		if n > 0 {
			p.workers = n
		}
	}
}

// NewEventPublisher creates a new EventPublisher.
func NewEventPublisher(bus eventbus.EventBus, resolver *cgroup.CgroupResolver, tracker *cgroup.ProcessTreeTracker, opts ...PublisherOption) *EventPublisher {
	p := &EventPublisher{
		bus:      bus,
		resolver: resolver,
		tracker:  tracker,
		workers:  defaultWorkers,
		events:   make(chan rawEvent, eventChannelBuffer),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Start starts the worker pool for event processing.
func (p *EventPublisher) Start(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	slog.Info("event publisher started", "workers", p.workers)
}

// PublishBatch submits a batch of raw events for processing.
func (p *EventPublisher) PublishBatch(batch [][]byte) {
	for _, data := range batch {
		select {
		case p.events <- rawEvent{data: data}:
		default:
			// Drop event if channel is full.
			p.metrics.PublishErrors.Add(1)
		}
	}
}

// worker processes events from the channel.
func (p *EventPublisher) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-p.events:
			if !ok {
				return
			}
			p.processEvent(evt)
		}
	}
}

// processEvent parses, enriches, and publishes a single event.
func (p *EventPublisher) processEvent(evt rawEvent) {
	p.metrics.EventsProcessed.Add(1)

	parsed, err := ParseEvent(evt.data)
	if err != nil {
		p.metrics.EnrichErrors.Add(1)
		slog.Debug("failed to parse eBPF event", "error", err)
		return
	}

	// Extract common fields and enrich with pod identity.
	busEvent := p.enrichEvent(parsed)
	if busEvent == nil {
		return
	}

	p.bus.Emit(busEvent)
	p.metrics.EventsPublished.Add(1)
}

// enrichEvent converts a parsed eBPF event to an eventbus.Event with pod identity.
func (p *EventPublisher) enrichEvent(parsed interface{}) eventbus.Event {
	var header *EventHeader
	var eventType string
	var subcategory string

	switch evt := parsed.(type) {
	case *ExecveEvent:
		header = &evt.Header
		eventType = "syscall.execve"
		subcategory = "execve"
	case *OpenatEvent:
		header = &evt.Header
		eventType = "syscall.openat"
		subcategory = "openat"
	case *ConnectEvent:
		header = &evt.Header
		eventType = "syscall.connect"
		subcategory = "connect"
	case *ForkEvent:
		header = &evt.Header
		eventType = "syscall.fork"
		subcategory = "fork"
		// Update process tree tracker.
		if p.tracker != nil {
			p.tracker.AddFork(evt.ParentPID, evt.ChildPID)
		}
	case *SetnsEvent:
		header = &evt.Header
		eventType = "security.setns"
		subcategory = "setns"
	case *UnshareEvent:
		header = &evt.Header
		eventType = "security.unshare"
		subcategory = "unshare"
	case *MountEvent:
		header = &evt.Header
		eventType = "security.mount"
		subcategory = "mount"
	case *PtraceEvent:
		header = &evt.Header
		eventType = "security.ptrace"
		subcategory = "ptrace"
	case *BPFSelfMonEvent:
		header = &evt.Header
		eventType = "security.unauthorized-bpf"
		subcategory = "unauthorized-bpf"
	default:
		return nil
	}

	// Resolve pod identity from cgroup ID.
	var agentInfo eventbus.AgentIdentity
	if p.resolver != nil {
		identity := p.resolver.Resolve(header.CgroupID)
		if identity != nil {
			agentInfo = eventbus.AgentIdentity{
				PodName:   identity.PodName,
				Namespace: identity.Namespace,
				Labels:    identity.Labels,
			}
		}
	}

	return &eventbus.BaseEvent{
		Type:      eventType,
		Time:      time.Now(),
		ReqID:     fmt.Sprintf("ebpf-%d-%d", header.PID, header.Timestamp),
		Proto:     "ebpf",
		Prov:      subcategory,
		AgentInfo: agentInfo,
	}
}

// Stop gracefully shuts down the publisher.
func (p *EventPublisher) Stop() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.events)
	p.mu.Unlock()

	p.wg.Wait()
	slog.Info("event publisher stopped",
		"events_published", p.metrics.EventsPublished.Load(),
		"events_processed", p.metrics.EventsProcessed.Load(),
	)
}

// Metrics returns the publisher's performance counters.
func (p *EventPublisher) Metrics() PublisherMetrics {
	return p.metrics
}
