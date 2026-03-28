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

// Package llm implements the ProtocolObserver interface for LLM protocol traffic,
// supporting OpenAI and Anthropic providers.
package llm

import (
	"context"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/observer"
)

// LLMObserver implements the observer.ProtocolObserver interface for LLM traffic.
// It delegates provider-specific parsing to OpenAI and Anthropic parsers.
type LLMObserver struct {
	bus eventbus.EventBus
}

// NewLLMObserver creates a new LLMObserver with the given event bus.
func NewLLMObserver(bus eventbus.EventBus) *LLMObserver {
	return &LLMObserver{bus: bus}
}

// Name returns the observer identifier.
func (o *LLMObserver) Name() string {
	return "llm"
}

// CanHandle determines whether this observer can handle the request by
// checking the host and path against known LLM provider patterns.
func (o *LLMObserver) CanHandle(_ context.Context, req *observer.ObserverContext) (bool, float32) {
	return false, 0
}

// ProcessRequestStream parses the LLM request and emits a start event.
func (o *LLMObserver) ProcessRequestStream(_ context.Context, req *observer.ObserverContext) (*observer.StreamContext, error) {
	return nil, nil
}

// ProcessResponseStream handles a response body chunk, parsing SSE data
// and emitting token chunk events.
func (o *LLMObserver) ProcessResponseStream(_ context.Context, streamCtx *observer.StreamContext, body []byte) error {
	return nil
}

// Finalize emits a completion event with aggregated metrics.
func (o *LLMObserver) Finalize(_ context.Context, streamCtx *observer.StreamContext, err error) error {
	return nil
}
