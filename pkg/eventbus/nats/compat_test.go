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

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// TestCompat_NATSBusAsEventBusInterface verifies NATSBus fully satisfies EventBus.
func TestCompat_NATSBusAsEventBusInterface(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	// Use the bus through the EventBus interface
	var eb eventbus.EventBus = bus

	sub := eb.Subscribe(eventbus.EventTypeLLMRequestStart)
	if sub == nil {
		t.Fatal("Subscribe() returned nil")
	}
	defer eb.Unsubscribe(sub)

	eb.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "compat-req-1",
		},
	})

	select {
	case received := <-sub.Events():
		if received.EventType() != eventbus.EventTypeLLMRequestStart {
			t.Errorf("EventType = %q, want %q", received.EventType(), eventbus.EventTypeLLMRequestStart)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

// TestCompat_AllLLMEventTypes verifies all LLM event types work through NATSBus.
func TestCompat_AllLLMEventTypes(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	var eb eventbus.EventBus = bus

	sub := eb.Subscribe(
		eventbus.EventTypeLLMRequestStart,
		eventbus.EventTypeLLMTokenChunk,
		eventbus.EventTypeLLMRequestComplete,
	)
	defer eb.Unsubscribe(sub)

	// Emit LLMRequestStartEvent
	eb.Emit(&eventbus.LLMRequestStartEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestStart,
			Time:  time.Now(),
			ReqID: "compat-start",
			Proto: eventbus.ProtocolLLM,
			Prov:  eventbus.ProviderOpenAI,
			AgentInfo: eventbus.AgentIdentity{
				ID:        "agent-test",
				Namespace: "default",
			},
		},
		Model:    "gpt-4",
		Messages: []string{"Hello"},
		Stream:   true,
	})

	select {
	case e := <-sub.Events():
		if e.EventType() != eventbus.EventTypeLLMRequestStart {
			t.Errorf("Start: EventType = %q, want %q", e.EventType(), eventbus.EventTypeLLMRequestStart)
		}
		if e.Protocol() != eventbus.ProtocolLLM {
			t.Errorf("Start: Protocol = %q, want %q", e.Protocol(), eventbus.ProtocolLLM)
		}
		if e.Provider() != eventbus.ProviderOpenAI {
			t.Errorf("Start: Provider = %q, want %q", e.Provider(), eventbus.ProviderOpenAI)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start: timed out")
	}

	// Emit LLMTokenChunkEvent
	eb.Emit(&eventbus.LLMTokenChunkEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "compat-chunk",
			Proto: eventbus.ProtocolLLM,
			Prov:  eventbus.ProviderOpenAI,
		},
		Content:    "world",
		TokenIndex: 1,
	})

	select {
	case e := <-sub.Events():
		if e.EventType() != eventbus.EventTypeLLMTokenChunk {
			t.Errorf("Chunk: EventType = %q, want %q", e.EventType(), eventbus.EventTypeLLMTokenChunk)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Chunk: timed out")
	}

	// Emit LLMRequestCompleteEvent
	eb.Emit(&eventbus.LLMRequestCompleteEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMRequestComplete,
			Time:  time.Now(),
			ReqID: "compat-complete",
			Proto: eventbus.ProtocolLLM,
			Prov:  eventbus.ProviderOpenAI,
		},
		TotalTokens:  100,
		InputTokens:  50,
		OutputTokens: 50,
		TTFT:         100 * time.Millisecond,
		Duration:     2 * time.Second,
		TokensPerSec: 50.0,
		FinishReason: "stop",
	})

	select {
	case e := <-sub.Events():
		if e.EventType() != eventbus.EventTypeLLMRequestComplete {
			t.Errorf("Complete: EventType = %q, want %q", e.EventType(), eventbus.EventTypeLLMRequestComplete)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Complete: timed out")
	}
}

// TestCompat_EventFilter verifies EventFilter works through NATSBus.
func TestCompat_EventFilter(t *testing.T) {
	bus, cleanup := newTestBus(t)
	defer cleanup()

	var eb eventbus.EventBus = bus

	// Subscribe with both protocol and provider filters
	filter := eventbus.EventFilter{
		Protocol: eventbus.ProtocolLLM,
		Provider: eventbus.ProviderAnthropic,
	}
	sub := eb.SubscribeWithFilter(filter, eventbus.EventTypeLLMTokenChunk)
	defer eb.Unsubscribe(sub)

	// Emit event with wrong provider (should NOT be received)
	eb.Emit(&eventbus.LLMTokenChunkEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "wrong-provider",
			Proto: eventbus.ProtocolLLM,
			Prov:  eventbus.ProviderOpenAI,
		},
	})

	select {
	case <-sub.Events():
		t.Error("Should not receive event with non-matching provider")
	case <-time.After(200 * time.Millisecond):
		// Expected
	}

	// Emit event with matching filters (should be received)
	eb.Emit(&eventbus.LLMTokenChunkEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypeLLMTokenChunk,
			Time:  time.Now(),
			ReqID: "matching-event",
			Proto: eventbus.ProtocolLLM,
			Prov:  eventbus.ProviderAnthropic,
		},
	})

	select {
	case e := <-sub.Events():
		if e.RequestID() != "matching-event" {
			t.Errorf("RequestID = %q, want %q", e.RequestID(), "matching-event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for matching event")
	}
}
