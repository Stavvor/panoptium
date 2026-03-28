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

import (
	"sync"
	"testing"
	"time"
)

// TestNewSimpleBus verifies that a new SimpleBus can be created.
func TestNewSimpleBus(t *testing.T) {
	bus := NewSimpleBus()
	if bus == nil {
		t.Fatal("NewSimpleBus() returned nil")
	}
	defer bus.Close()
}

// TestSubscribe verifies that a subscriber can be registered and receives events.
func TestSubscribe(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(EventTypeLLMRequestStart)
	if sub == nil {
		t.Fatal("Subscribe() returned nil")
	}
	defer bus.Unsubscribe(sub)

	ch := sub.Events()
	if ch == nil {
		t.Fatal("Events() channel is nil")
	}
}

// TestSubscribeMultipleTypes verifies subscription to multiple event types.
func TestSubscribeMultipleTypes(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(EventTypeLLMRequestStart, EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(sub)

	// Emit a matching event
	event := &LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-1",
		},
	}
	bus.Emit(event)

	select {
	case received := <-sub.Events():
		if received.EventType() != EventTypeLLMRequestStart {
			t.Errorf("received event type %q, want %q", received.EventType(), EventTypeLLMRequestStart)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

// TestUnsubscribe verifies that an unsubscribed subscriber no longer receives events.
func TestUnsubscribe(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(EventTypeLLMRequestStart)
	bus.Unsubscribe(sub)

	event := &LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-1",
		},
	}
	bus.Emit(event)

	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Error("should not receive events after unsubscribe")
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: no event received
	}
}

// TestEmitToMultipleSubscribers verifies that multiple subscribers all receive the same event.
func TestEmitToMultipleSubscribers(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	sub1 := bus.Subscribe(EventTypeLLMRequestStart)
	sub2 := bus.Subscribe(EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub1)
	defer bus.Unsubscribe(sub2)

	event := &LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-multi",
		},
	}
	bus.Emit(event)

	for i, sub := range []*Subscription{sub1, sub2} {
		select {
		case received := <-sub.Events():
			if received.RequestID() != "req-multi" {
				t.Errorf("subscriber %d: RequestID = %q, want %q", i, received.RequestID(), "req-multi")
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out waiting for event", i)
		}
	}
}

// TestEventTypeFiltering verifies that subscribers only receive events matching their type filter.
func TestEventTypeFiltering(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	subStart := bus.Subscribe(EventTypeLLMRequestStart)
	subChunk := bus.Subscribe(EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(subStart)
	defer bus.Unsubscribe(subChunk)

	// Emit a token chunk event
	chunkEvent := &LLMTokenChunkEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "req-filter",
		},
		Content: "token",
	}
	bus.Emit(chunkEvent)

	// subChunk should receive it
	select {
	case received := <-subChunk.Events():
		if received.EventType() != EventTypeLLMTokenChunk {
			t.Errorf("subChunk received type %q, want %q", received.EventType(), EventTypeLLMTokenChunk)
		}
	case <-time.After(time.Second):
		t.Fatal("subChunk: timed out waiting for event")
	}

	// subStart should NOT receive it
	select {
	case <-subStart.Events():
		t.Error("subStart should not receive LLMTokenChunk events")
	case <-time.After(100 * time.Millisecond):
		// Expected: no event
	}
}

// TestNonBlockingBehavior verifies that a slow subscriber does not block the publisher.
func TestNonBlockingBehavior(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	// Create a subscriber but never read from it — simulates a slow subscriber
	slowSub := bus.Subscribe(EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(slowSub)

	// Emit many events — should not block
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			bus.Emit(&LLMTokenChunkEvent{
				BaseEvent: BaseEvent{
					Type:  EventTypeLLMTokenChunk,
					Time:  time.Now(),
					ReqID: "req-nonblock",
				},
				Content: "token",
			})
		}
		close(done)
	}()

	select {
	case <-done:
		// OK: emissions completed without blocking
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked due to slow subscriber")
	}
}

// TestSubscribeWithFilter_Protocol verifies filtering by protocol.
func TestSubscribeWithFilter_Protocol(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	filter := EventFilter{
		Protocol: ProtocolLLM,
	}
	sub := bus.SubscribeWithFilter(filter, EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	// Emit an event with matching protocol
	matchEvent := &LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-proto-match",
			Proto: ProtocolLLM,
		},
	}
	bus.Emit(matchEvent)

	select {
	case received := <-sub.Events():
		if received.RequestID() != "req-proto-match" {
			t.Errorf("RequestID = %q, want %q", received.RequestID(), "req-proto-match")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for matching event")
	}
}

// TestSubscribeWithFilter_Provider verifies filtering by provider.
func TestSubscribeWithFilter_Provider(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	filter := EventFilter{
		Provider: ProviderOpenAI,
	}
	sub := bus.SubscribeWithFilter(filter, EventTypeLLMRequestStart)
	defer bus.Unsubscribe(sub)

	// Emit an event with non-matching provider
	noMatchEvent := &LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-anthropic",
			Prov:  ProviderAnthropic,
		},
	}
	bus.Emit(noMatchEvent)

	// Should not receive it
	select {
	case <-sub.Events():
		t.Error("should not receive event with non-matching provider")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}

	// Emit an event with matching provider
	matchEvent := &LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-openai",
			Prov:  ProviderOpenAI,
		},
	}
	bus.Emit(matchEvent)

	select {
	case received := <-sub.Events():
		if received.RequestID() != "req-openai" {
			t.Errorf("RequestID = %q, want %q", received.RequestID(), "req-openai")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for matching event")
	}
}

// TestSubscribeWithFilter_ProtocolAndProvider verifies filtering by both protocol and provider.
func TestSubscribeWithFilter_ProtocolAndProvider(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	filter := EventFilter{
		Protocol: ProtocolLLM,
		Provider: ProviderAnthropic,
	}
	sub := bus.SubscribeWithFilter(filter, EventTypeLLMTokenChunk)
	defer bus.Unsubscribe(sub)

	// Emit event with matching protocol but wrong provider
	bus.Emit(&LLMTokenChunkEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "req-wrong-provider",
			Proto: ProtocolLLM,
			Prov:  ProviderOpenAI,
		},
	})

	select {
	case <-sub.Events():
		t.Error("should not receive event with non-matching provider")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}

	// Emit event with both matching
	bus.Emit(&LLMTokenChunkEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "req-both-match",
			Proto: ProtocolLLM,
			Prov:  ProviderAnthropic,
		},
	})

	select {
	case received := <-sub.Events():
		if received.RequestID() != "req-both-match" {
			t.Errorf("RequestID = %q, want %q", received.RequestID(), "req-both-match")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for matching event")
	}
}

// TestBusClose verifies that closing the bus stops event delivery.
func TestBusClose(t *testing.T) {
	bus := NewSimpleBus()

	sub := bus.Subscribe(EventTypeLLMRequestStart)

	bus.Close()

	// After close, the subscriber's channel should be closed
	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Error("expected subscriber channel to be closed after bus close")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}

// TestBusClose_EmitAfterClose verifies that emitting after close does not panic.
func TestBusClose_EmitAfterClose(t *testing.T) {
	bus := NewSimpleBus()
	bus.Close()

	// This should not panic
	bus.Emit(&LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-after-close",
		},
	})
}

// TestBusClose_SubscribeAfterClose verifies that subscribing after close returns nil.
func TestBusClose_SubscribeAfterClose(t *testing.T) {
	bus := NewSimpleBus()
	bus.Close()

	sub := bus.Subscribe(EventTypeLLMRequestStart)
	if sub != nil {
		t.Error("Subscribe after Close should return nil")
	}
}

// TestConcurrentEmitAndSubscribe verifies thread safety of concurrent operations.
func TestConcurrentEmitAndSubscribe(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	var wg sync.WaitGroup

	// Spawn multiple goroutines that subscribe and unsubscribe
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub := bus.Subscribe(EventTypeLLMTokenChunk)
			if sub == nil {
				return
			}
			// Read a few events
			for j := 0; j < 5; j++ {
				select {
				case <-sub.Events():
				case <-time.After(100 * time.Millisecond):
				}
			}
			bus.Unsubscribe(sub)
		}()
	}

	// Spawn emitters
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				bus.Emit(&LLMTokenChunkEvent{
					BaseEvent: BaseEvent{
						Type:  EventTypeLLMTokenChunk,
						Time:  time.Now(),
						ReqID: "req-concurrent",
					},
				})
			}
		}()
	}

	wg.Wait()
}

// TestSubscribeAll verifies that subscribing without event types receives all events.
func TestSubscribeAll(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe() // No event type filter = receive all
	defer bus.Unsubscribe(sub)

	bus.Emit(&LLMRequestStartEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "req-all-1",
		},
	})

	bus.Emit(&LLMTokenChunkEvent{
		BaseEvent: BaseEvent{
			Type:  EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "req-all-2",
		},
	})

	received := 0
	for i := 0; i < 2; i++ {
		select {
		case <-sub.Events():
			received++
		case <-time.After(time.Second):
			t.Fatalf("timed out, received %d/2 events", received)
		}
	}
	if received != 2 {
		t.Errorf("received %d events, want 2", received)
	}
}

// TestUnsubscribeIdempotent verifies that calling Unsubscribe multiple times is safe.
func TestUnsubscribeIdempotent(t *testing.T) {
	bus := NewSimpleBus()
	defer bus.Close()

	sub := bus.Subscribe(EventTypeLLMRequestStart)
	bus.Unsubscribe(sub)
	bus.Unsubscribe(sub) // Should not panic
}
