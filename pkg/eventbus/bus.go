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

package eventbus

import "sync"

const (
	// defaultBufferSize is the default channel buffer size per subscriber.
	// Events are dropped (not buffered indefinitely) if a subscriber is slow.
	defaultBufferSize = 256
)

// EventFilter defines optional filtering criteria for event subscriptions.
// Empty string fields are treated as "match all".
type EventFilter struct {
	// Protocol filters events by protocol (e.g., "llm").
	Protocol string

	// Provider filters events by provider (e.g., "openai", "anthropic").
	Provider string
}

// Subscription represents a subscriber's connection to the event bus.
type Subscription struct {
	ch         chan Event
	eventTypes map[string]bool // empty map means "all types"
	filter     EventFilter
	closed     bool
	mu         sync.Mutex
}

// NewSubscription creates a new Subscription with the given event types, filter,
// and buffer size. This is intended for use by EventBus implementations.
func NewSubscription(eventTypes []string, filter EventFilter, bufferSize int) *Subscription {
	typeMap := make(map[string]bool, len(eventTypes))
	for _, t := range eventTypes {
		typeMap[t] = true
	}
	return &Subscription{
		ch:         make(chan Event, bufferSize),
		eventTypes: typeMap,
		filter:     filter,
	}
}

// Events returns the channel on which the subscriber receives events.
func (s *Subscription) Events() <-chan Event {
	return s.ch
}

// Ch returns the writable channel for sending events to this subscription.
// This is intended for use by EventBus implementations.
func (s *Subscription) Ch() chan<- Event {
	return s.ch
}

// Close closes the subscription's channel. It is safe to call multiple times.
func (s *Subscription) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

// close is a package-private alias for Close, preserved for backward compatibility.
func (s *Subscription) close() {
	s.Close()
}

// EventBus defines the interface for an event bus that supports
// publishing and subscribing to events.
type EventBus interface {
	// Subscribe registers a subscriber for the specified event types.
	// If no event types are provided, the subscriber receives all events.
	// Returns nil if the bus is closed.
	Subscribe(eventTypes ...string) *Subscription

	// SubscribeWithFilter registers a subscriber with additional filtering.
	// Returns nil if the bus is closed.
	SubscribeWithFilter(filter EventFilter, eventTypes ...string) *Subscription

	// Unsubscribe removes a subscriber from the bus.
	// Safe to call multiple times.
	Unsubscribe(sub *Subscription)

	// Emit publishes an event to all matching subscribers.
	// Non-blocking: if a subscriber's buffer is full, the event is dropped for that subscriber.
	// Safe to call after Close (no-op).
	Emit(event Event)

	// Close shuts down the event bus and closes all subscriber channels.
	Close()
}

// SimpleBus is a Go channel-based implementation of EventBus.
type SimpleBus struct {
	mu          sync.RWMutex
	subscribers map[*Subscription]struct{}
	closed      bool
}

// NewSimpleBus creates a new SimpleBus event bus.
func NewSimpleBus() *SimpleBus {
	return &SimpleBus{
		subscribers: make(map[*Subscription]struct{}),
	}
}

// Subscribe registers a subscriber for the specified event types.
// If no event types are provided, the subscriber receives all events.
// Returns nil if the bus is already closed.
func (b *SimpleBus) Subscribe(eventTypes ...string) *Subscription {
	return b.SubscribeWithFilter(EventFilter{}, eventTypes...)
}

// SubscribeWithFilter registers a subscriber with additional filtering criteria.
// Returns nil if the bus is already closed.
func (b *SimpleBus) SubscribeWithFilter(filter EventFilter, eventTypes ...string) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	typeMap := make(map[string]bool, len(eventTypes))
	for _, t := range eventTypes {
		typeMap[t] = true
	}

	sub := &Subscription{
		ch:         make(chan Event, defaultBufferSize),
		eventTypes: typeMap,
		filter:     filter,
	}

	b.subscribers[sub] = struct{}{}
	return sub
}

// Unsubscribe removes a subscriber from the bus and closes its channel.
// Safe to call multiple times and with nil.
func (b *SimpleBus) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}

	b.mu.Lock()
	_, exists := b.subscribers[sub]
	if exists {
		delete(b.subscribers, sub)
	}
	b.mu.Unlock()

	if exists {
		sub.close()
	}
}

// Emit publishes an event to all matching subscribers.
// Non-blocking: if a subscriber's buffer is full, the event is dropped.
// Safe to call after Close (no-op).
func (b *SimpleBus) Emit(event Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	for sub := range b.subscribers {
		if !b.matches(sub, event) {
			continue
		}

		// Non-blocking send: drop event if subscriber buffer is full
		select {
		case sub.ch <- event:
		default:
		}
	}
}

// Close shuts down the event bus and closes all subscriber channels.
func (b *SimpleBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.closed = true

	for sub := range b.subscribers {
		sub.close()
		delete(b.subscribers, sub)
	}
}

// matches checks whether an event matches a subscription's filters.
func (b *SimpleBus) matches(sub *Subscription, event Event) bool {
	// Check event type filter
	if len(sub.eventTypes) > 0 && !sub.eventTypes[event.EventType()] {
		return false
	}

	// Check protocol filter
	if sub.filter.Protocol != "" && event.Protocol() != sub.filter.Protocol {
		return false
	}

	// Check provider filter
	if sub.filter.Provider != "" && event.Provider() != sub.filter.Provider {
		return false
	}

	return true
}
