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

// TestLLMObserver_ProcessRequestStream_OpenAI_ToolNames verifies that tool names
// from the OpenAI request body are propagated to the StreamContext.
func TestLLMObserver_ProcessRequestStream_OpenAI_ToolNames(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	body := []byte(`{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Do something"}],
		"tools": [
			{"type": "function", "function": {"name": "get_weather"}},
			{"type": "function", "function": {"name": "dangerous_exec"}}
		],
		"stream": true
	}`)

	req := &observer.ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-tool-propagation-1",
		Headers:   http.Header{},
		Body:      body,
	}

	streamCtx, err := obs.ProcessRequestStream(ctx, req)
	if err != nil {
		t.Fatalf("ProcessRequestStream() error = %v", err)
	}
	if streamCtx == nil {
		t.Fatal("ProcessRequestStream() returned nil StreamContext")
	}
	if len(streamCtx.ToolNames) != 2 {
		t.Fatalf("StreamContext.ToolNames count = %d, want 2", len(streamCtx.ToolNames))
	}
	if streamCtx.ToolNames[0] != "get_weather" {
		t.Errorf("ToolNames[0] = %q, want %q", streamCtx.ToolNames[0], "get_weather")
	}
	if streamCtx.ToolNames[1] != "dangerous_exec" {
		t.Errorf("ToolNames[1] = %q, want %q", streamCtx.ToolNames[1], "dangerous_exec")
	}
}

// TestLLMObserver_ProcessRequestStream_Anthropic_ToolNames verifies that tool names
// from the Anthropic request body are propagated to the StreamContext.
func TestLLMObserver_ProcessRequestStream_Anthropic_ToolNames(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	body := []byte(`{
		"model": "claude-3-opus-20240229",
		"messages": [{"role": "user", "content": "Do something"}],
		"tools": [
			{"name": "read_file", "description": "reads a file"}
		],
		"max_tokens": 1024,
		"stream": true
	}`)

	req := &observer.ObserverContext{
		Path:      "/v1/messages",
		Method:    "POST",
		RequestID: "req-tool-propagation-2",
		Headers:   http.Header{},
		Body:      body,
	}

	streamCtx, err := obs.ProcessRequestStream(ctx, req)
	if err != nil {
		t.Fatalf("ProcessRequestStream() error = %v", err)
	}
	if streamCtx == nil {
		t.Fatal("ProcessRequestStream() returned nil StreamContext")
	}
	if len(streamCtx.ToolNames) != 1 {
		t.Fatalf("StreamContext.ToolNames count = %d, want 1", len(streamCtx.ToolNames))
	}
	if streamCtx.ToolNames[0] != "read_file" {
		t.Errorf("ToolNames[0] = %q, want %q", streamCtx.ToolNames[0], "read_file")
	}
}

// TestLLMObserver_ProcessRequestStream_NoTools verifies that StreamContext.ToolNames
// is empty when no tools are present in the request body.
func TestLLMObserver_ProcessRequestStream_NoTools(t *testing.T) {
	bus := eventbus.NewSimpleBus()
	defer bus.Close()

	obs := NewLLMObserver(bus)
	ctx := context.Background()

	body := []byte(`{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Hello"}],
		"stream": true
	}`)

	req := &observer.ObserverContext{
		Path:      "/v1/chat/completions",
		Method:    "POST",
		RequestID: "req-no-tools",
		Headers:   http.Header{},
		Body:      body,
	}

	streamCtx, err := obs.ProcessRequestStream(ctx, req)
	if err != nil {
		t.Fatalf("ProcessRequestStream() error = %v", err)
	}
	if len(streamCtx.ToolNames) != 0 {
		t.Errorf("StreamContext.ToolNames count = %d, want 0", len(streamCtx.ToolNames))
	}
}
