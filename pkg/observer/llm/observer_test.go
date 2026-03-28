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

package llm

import (
	"context"
	"net/http"
	"testing"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer"
)

// TestLLMObserver_Name verifies the observer returns its identifier.
func TestLLMObserver_Name(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	if obs.Name() != "llm" {
		t.Errorf("Name() = %q, want %q", obs.Name(), "llm")
	}
}

// TestLLMObserver_CanHandle_OpenAI verifies detection of OpenAI requests by path.
func TestLLMObserver_CanHandle_OpenAI(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	req := &observer.ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-openai-1",
		Headers:   http.Header{},
	}

	canHandle, confidence := obs.CanHandle(ctx, req)
	if !canHandle {
		t.Error("CanHandle() returned false for OpenAI path, want true")
	}
	if confidence <= 0 {
		t.Errorf("CanHandle() confidence = %f, want > 0", confidence)
	}
}

// TestLLMObserver_CanHandle_Anthropic verifies detection of Anthropic requests by path.
func TestLLMObserver_CanHandle_Anthropic(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	req := &observer.ObserverContext{
		Path:      "/v1/messages",
		Method:    "POST",
		RequestID: "req-anthropic-1",
		Headers:   http.Header{},
	}

	canHandle, confidence := obs.CanHandle(ctx, req)
	if !canHandle {
		t.Error("CanHandle() returned false for Anthropic path, want true")
	}
	if confidence <= 0 {
		t.Errorf("CanHandle() confidence = %f, want > 0", confidence)
	}
}

// TestLLMObserver_CanHandle_UnknownPath verifies rejection of unknown paths.
func TestLLMObserver_CanHandle_UnknownPath(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	req := &observer.ObserverContext{
		Path:      "/api/unknown",
		Method:    "POST",
		RequestID: "req-unknown",
		Headers:   http.Header{},
	}

	canHandle, confidence := obs.CanHandle(ctx, req)
	if canHandle {
		t.Error("CanHandle() returned true for unknown path, want false")
	}
	if confidence != 0 {
		t.Errorf("CanHandle() confidence = %f, want 0 for unknown path", confidence)
	}
}

// TestLLMObserver_CanHandle_OpenAI_WithHost verifies detection using x-forwarded-host for OpenAI.
func TestLLMObserver_CanHandle_OpenAI_WithHost(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	headers := http.Header{}
	headers.Set("Host", "api.openai.com")

	req := &observer.ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-openai-host",
		Headers:   headers,
	}

	canHandle, confidence := obs.CanHandle(ctx, req)
	if !canHandle {
		t.Error("CanHandle() returned false for OpenAI host + path, want true")
	}
	// Host matching should give higher confidence
	if confidence < 0.8 {
		t.Errorf("CanHandle() confidence = %f, want >= 0.8 for host match", confidence)
	}
}

// TestLLMObserver_CanHandle_Anthropic_WithHost verifies detection using host for Anthropic.
func TestLLMObserver_CanHandle_Anthropic_WithHost(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	headers := http.Header{}
	headers.Set("Host", "api.anthropic.com")

	req := &observer.ObserverContext{
		Path:      "/v1/messages",
		Method:    "POST",
		RequestID: "req-anthropic-host",
		Headers:   headers,
	}

	canHandle, confidence := obs.CanHandle(ctx, req)
	if !canHandle {
		t.Error("CanHandle() returned false for Anthropic host + path, want true")
	}
	if confidence < 0.8 {
		t.Errorf("CanHandle() confidence = %f, want >= 0.8 for host match", confidence)
	}
}

// TestLLMObserver_ImplementsInterface verifies LLMObserver satisfies ProtocolObserver.
func TestLLMObserver_ImplementsInterface(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	var _ observer.ProtocolObserver = NewLLMObserver(bus)
}
