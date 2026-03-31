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

// Package observer defines the ProtocolObserver interface and ObserverRegistry
// for extensible, multi-provider protocol observation in the Panoptium operator.
package observer

import (
	"context"
	"net/http"
	"time"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// ProtocolObserver defines the interface for protocol-specific observers that
// decouple parsing logic from the ExtProc server. Each implementation handles
// a specific protocol/provider combination (e.g., OpenAI LLM, Anthropic LLM).
type ProtocolObserver interface {
	// Name returns a unique identifier for this observer (e.g., "llm-openai").
	Name() string

	// CanHandle determines whether this observer can handle the given request
	// context. Returns true/false and a confidence score (0.0 to 1.0).
	CanHandle(ctx context.Context, req *ObserverContext) (bool, float32)

	// ProcessRequestStream parses the request and emits start events.
	// Returns a StreamContext that tracks the request state through its lifecycle.
	ProcessRequestStream(ctx context.Context, req *ObserverContext) (*StreamContext, error)

	// ProcessResponseStream handles a response body chunk, parsing it for tokens
	// and emitting chunk events via the StreamContext's event bus.
	ProcessResponseStream(ctx context.Context, streamCtx *StreamContext, body []byte) error

	// Finalize is called when the stream ends. It emits completion events with
	// aggregated metrics.
	Finalize(ctx context.Context, streamCtx *StreamContext, err error) error
}

// ObserverContext contains the request metadata available to observers for
// protocol detection and request parsing.
type ObserverContext struct {
	// Headers contains the HTTP request headers.
	Headers http.Header

	// Path is the HTTP request path (e.g., "/v1/chat/completions").
	Path string

	// Method is the HTTP method (e.g., "POST").
	Method string

	// RequestID is the unique request correlation ID.
	RequestID string

	// Body contains the full request body (if buffered).
	Body []byte
}

// StreamContext tracks the state of an observed request through its lifecycle.
// It is created by ProcessRequestStream and passed to ProcessResponseStream
// and Finalize.
type StreamContext struct {
	// RequestID is the unique request correlation ID.
	RequestID string

	// Protocol is the detected protocol (e.g., "llm").
	Protocol string

	// Provider is the detected provider (e.g., "openai", "anthropic").
	Provider string

	// StartTime is when the request was first observed.
	StartTime time.Time

	// EventBus is the event bus for publishing observation events.
	EventBus eventbus.EventBus

	// AgentIdentity is the resolved identity of the agent making the request.
	AgentIdentity eventbus.AgentIdentity

	// Model is the LLM model being called.
	Model string

	// Stream indicates whether the request uses streaming mode.
	Stream bool

	// TokenCount tracks the number of output tokens observed so far.
	TokenCount int

	// FirstTokenTime records the time the first token was observed.
	FirstTokenTime time.Time

	// RequestBody stores the raw request body for deferred parsing.
	RequestBody []byte

	// ToolNames contains tool function names extracted from the request body.
	// Populated by the LLM observer from provider-specific parsing
	// (OpenAI tools[].function.name, Anthropic tools[].name).
	ToolNames []string
}

// ObserverConfig defines the configuration for registering an observer.
type ObserverConfig struct {
	// Name is the unique identifier for the observer.
	Name string

	// Priority determines the order in which observers are consulted.
	// Lower values indicate higher priority.
	Priority int

	// Protocol is the protocol this observer handles (e.g., "llm").
	Protocol string

	// Providers lists the providers this observer supports.
	Providers []string
}
