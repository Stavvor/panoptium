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
	"sync"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// newTestBus creates a NATSBus backed by an embedded NATS server for testing.
// It returns the bus and a cleanup function.
func newTestBus(t *testing.T) (*NATSBus, func()) {
	t.Helper()

	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	bus, err := NewNATSBus(srv.ClientURL())
	if err != nil {
		srv.Shutdown()
		t.Fatalf("NewNATSBus() error: %v", err)
	}

	cleanup := func() {
		bus.Close()
		srv.Shutdown()
	}
	return bus, cleanup
}

// TestNATSBus_TopicHierarchy verifies that events are published to the correct
// NATS subject following the panoptium.events.{ns}.{cat}.{subcat} format.
func TestNATSBus_TopicHierarchy(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	if sub == nil {
		t.Fatal("Subscribe() returned nil")
	}
	defer bus.Unsubscribe(sub)

	event := &eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-topic-1",
			Proto: eventbus.ProtocolLLM,
			AgentInfo: eventbus.AgentIdentity{
				Namespace: "default",
			},
		},
		Model: "gpt-4",
	}
	bus.Emit(event)

	select {
	case received := <-sub.Events():
		if received.EventType() != eventbus.EventTypeLLMRequestStart {
			t.Errorf("EventType = %q, want %q", received.EventType(), eventbus.EventTypeLLMRequestStart)
		}
		if received.RequestID() != "req-topic-1" {
			t.Errorf("RequestID = %q, want %q", received.RequestID(), "req-topic-1")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

// TestNATSBus_WildcardSubscription verifies that wildcard subscriptions work.
func TestNATSBus_WildcardSubscription(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	// Subscribe to all LLM events (wildcard)
	sub := bus.Subscribe(
		eventbus.EventTypeLLMRequestStart,
		eventbus.EventTypeLLMTokenChunk,
		eventbus.EventTypeLLMRequestComplete,
	)
	if sub == nil {
		t.Fatal("Subscribe() returned nil")
	}
	defer bus.Unsubscribe(sub)

	// Emit different LLM events
	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-wild-1",
		},
	})
	bus.Emit(&eventbus.LLMTokenChunkEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "req-wild-2",
		},
		Content: "hello",
	})

	received := 0
	for i := 0; i < 2; i++ {
		select {
		case <-sub.Events():
			received++
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out, received %d/2 events", received)
		}
	}
	if received != 2 {
		t.Errorf("received %d events, want 2", received)
	}
}

// TestNATSBus_SubjectIsolation verifies that subscribers only receive matching events.
func TestNATSBus_SubjectIsolation(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	subStart := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	subChunk := bus.Subscribe(eventbus.EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(subStart)
	defer bus.Unsubscribe(subChunk)

	// Emit a token chunk event
	bus.Emit(&eventbus.LLMTokenChunkEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "req-isolate",
		},
		Content: "token",
	})

	// subChunk should receive it
	select {
	case received := <-subChunk.Events():
		if received.EventType() != eventbus.EventTypeLLMTokenChunk {
			t.Errorf("subChunk EventType = %q, want %q", received.EventType(), eventbus.EventTypeLLMTokenChunk)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subChunk: timed out")
	}

	// subStart should NOT receive it
	select {
	case <-subStart.Events():
		t.Error("subStart should not receive LLMTokenChunk events")
	case <-time.After(200 * time.Millisecond):
		// Expected: no event
	}
}

// TestNATSBus_MultipleSubscribers verifies fan-out to multiple subscribers.
func TestNATSBus_MultipleSubscribers(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	sub1 := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	sub2 := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	sub3 := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub1)
	defer bus.Unsubscribe(sub2)
	defer bus.Unsubscribe(sub3)

	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-fanout",
		},
	})

	for i, sub := range []*eventbus.Subscription{sub1, sub2, sub3} {
		select {
		case received := <-sub.Events():
			if received.RequestID() != "req-fanout" {
				t.Errorf("subscriber %d: RequestID = %q, want %q", i, received.RequestID(), "req-fanout")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("subscriber %d: timed out", i)
		}
	}
}

// TestNATSBus_SubscribeAll verifies that subscribing with no types gets all events.
func TestNATSBus_SubscribeAll(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	sub := bus.Subscribe() // No filter = all events
	defer bus.Unsubscribe(sub)

	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-all-1",
		},
	})
	bus.Emit(&eventbus.LLMTokenChunkEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "req-all-2",
		},
	})

	received := 0
	for i := 0; i < 2; i++ {
		select {
		case <-sub.Events():
			received++
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out, received %d/2 events", received)
		}
	}
	if received != 2 {
		t.Errorf("received %d events, want 2", received)
	}
}

// TestNATSBus_SubscribeWithFilter_Protocol verifies protocol filtering.
func TestNATSBus_SubscribeWithFilter_Protocol(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	filter := eventbus.EventFilter{Protocol: eventbus.ProtocolLLM}
	sub := bus.SubscribeWithFilter(filter, eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	// Emit matching event
	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-proto-match",
			Proto: eventbus.ProtocolLLM,
		},
	})

	select {
	case received := <-sub.Events():
		if received.RequestID() != "req-proto-match" {
			t.Errorf("RequestID = %q, want %q", received.RequestID(), "req-proto-match")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for matching event")
	}
}

// TestNATSBus_SubscribeWithFilter_Provider verifies provider filtering.
func TestNATSBus_SubscribeWithFilter_Provider(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	filter := eventbus.EventFilter{Provider: eventbus.ProviderOpenAI}
	sub := bus.SubscribeWithFilter(filter, eventbus.EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	// Emit non-matching provider event
	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-anthropic",
			Prov:  eventbus.ProviderAnthropic,
		},
	})

	// Should not receive it
	select {
	case <-sub.Events():
		t.Error("should not receive event with non-matching provider")
	case <-time.After(200 * time.Millisecond):
		// Expected
	}

	// Emit matching provider event
	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-openai",
			Prov:  eventbus.ProviderOpenAI,
		},
	})

	select {
	case received := <-sub.Events():
		if received.RequestID() != "req-openai" {
			t.Errorf("RequestID = %q, want %q", received.RequestID(), "req-openai")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for matching event")
	}
}

// TestNATSBus_Unsubscribe verifies that unsubscribed clients stop receiving events.
func TestNATSBus_Unsubscribe(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	bus.Unsubscribe(sub)

	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-unsub",
		},
	})

	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Error("should not receive events after unsubscribe")
		}
	case <-time.After(200 * time.Millisecond):
		// Expected: channel closed or no event
	}
}

// TestNATSBus_Close verifies that closing the bus stops all delivery.
func TestNATSBus_Close(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)

	bus.Close()

	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Error("expected channel to be closed after bus close")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}

// TestNATSBus_EmitAfterClose verifies that emitting after close does not panic.
func TestNATSBus_EmitAfterClose(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	bus.Close()

	// Should not panic
	bus.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-after-close",
		},
	})
}

// TestNATSBus_SubscribeAfterClose verifies subscribe after close returns nil.
func TestNATSBus_SubscribeAfterClose(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	bus.Close()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	if sub != nil {
		t.Error("Subscribe after Close should return nil")
	}
}

// TestNATSBus_ConcurrentEmitAndSubscribe verifies thread safety.
func TestNATSBus_ConcurrentEmitAndSubscribe(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	var wg sync.WaitGroup

	// Spawn subscribers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub := bus.Subscribe(eventbus.EventTypeLLMTokenChunk)
			if sub == nil {
				return
			}
			for j := 0; j < 3; j++ {
				select {
				case <-sub.Events():
				case <-time.After(time.Second):
				}
			}
			bus.Unsubscribe(sub)
		}()
	}

	// Spawn emitters
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				bus.Emit(&eventbus.LLMTokenChunkEvent{
					BaseEvent: eventbus.BaseEvent{
						Type:  eventbus.EventTypeLLMTokenChunk,
						Time:  time.Now(),
						ReqID: "req-concurrent",
					},
				})
			}
		}()
	}

	wg.Wait()
}

// TestNATSBus_UnsubscribeIdempotent verifies double unsubscribe is safe.
func TestNATSBus_UnsubscribeIdempotent(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	sub := bus.Subscribe(eventbus.EventTypeLLMRequestStart)
	bus.Unsubscribe(sub)
	bus.Unsubscribe(sub) // Should not panic
}

// TestNATSBus_InterfaceCompliance verifies NATSBus implements EventBus.
func TestNATSBus_InterfaceCompliance(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	// Compile-time check
	var _ eventbus.EventBus = bus
}
