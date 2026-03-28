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

package openai

import (
	"testing"
)

// --- Request Parsing Tests ---

// TestParseRequest_Basic verifies parsing a basic OpenAI chat completion request.
func TestParseRequest_Basic(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Hello, world!"}
		],
		"stream": true
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if req == nil {
		t.Fatal("ParseRequest() returned nil")
	}
	if req.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", req.Model, "gpt-4")
	}
	if len(req.Messages) != 2 {
		t.Fatalf("Messages count = %d, want 2", len(req.Messages))
	}
	if req.Messages[0].Role != "system" {
		t.Errorf("Messages[0].Role = %q, want %q", req.Messages[0].Role, "system")
	}
	if req.Messages[0].Content != "You are a helpful assistant." {
		t.Errorf("Messages[0].Content = %q, want %q", req.Messages[0].Content, "You are a helpful assistant.")
	}
	if req.Messages[1].Role != "user" {
		t.Errorf("Messages[1].Role = %q, want %q", req.Messages[1].Role, "user")
	}
	if req.Messages[1].Content != "Hello, world!" {
		t.Errorf("Messages[1].Content = %q, want %q", req.Messages[1].Content, "Hello, world!")
	}
	if !req.Stream {
		t.Error("Stream = false, want true")
	}
}

// TestParseRequest_NonStreaming verifies parsing with stream=false.
func TestParseRequest_NonStreaming(t *testing.T) {
	body := []byte(`{
		"model": "gpt-3.5-turbo",
		"messages": [{"role": "user", "content": "Hi"}],
		"stream": false
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if req.Stream {
		t.Error("Stream = true, want false")
	}
	if req.Model != "gpt-3.5-turbo" {
		t.Errorf("Model = %q, want %q", req.Model, "gpt-3.5-turbo")
	}
}

// TestParseRequest_NoStreamField verifies default stream=false when field is absent.
func TestParseRequest_NoStreamField(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Hi"}]
	}`)

	req, err := ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if req.Stream {
		t.Error("Stream = true, want false when field is absent")
	}
}

// TestParseRequest_InvalidJSON verifies error on malformed JSON.
func TestParseRequest_InvalidJSON(t *testing.T) {
	body := []byte(`{invalid json}`)

	_, err := ParseRequest(body)
	if err == nil {
		t.Fatal("ParseRequest() expected error for invalid JSON, got nil")
	}
}

// --- SSE Streaming Response Parsing Tests ---

// TestParseSSEChunk_SingleToken verifies parsing a single SSE data line with a token.
func TestParseSSEChunk_SingleToken(t *testing.T) {
	data := []byte(`{"id":"chatcmpl-123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`)

	chunk, err := ParseSSEChunk(data)
	if err != nil {
		t.Fatalf("ParseSSEChunk() error = %v", err)
	}
	if chunk == nil {
		t.Fatal("ParseSSEChunk() returned nil")
	}
	if chunk.Content != "Hello" {
		t.Errorf("Content = %q, want %q", chunk.Content, "Hello")
	}
	if chunk.Done {
		t.Error("Done = true, want false")
	}
	if chunk.FinishReason != "" {
		t.Errorf("FinishReason = %q, want empty", chunk.FinishReason)
	}
}

// TestParseSSEChunk_WithFinishReason verifies parsing a chunk with finish_reason set.
func TestParseSSEChunk_WithFinishReason(t *testing.T) {
	data := []byte(`{"id":"chatcmpl-123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)

	chunk, err := ParseSSEChunk(data)
	if err != nil {
		t.Fatalf("ParseSSEChunk() error = %v", err)
	}
	if chunk.FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want %q", chunk.FinishReason, "stop")
	}
}

// TestParseSSEChunk_EmptyDelta verifies parsing a chunk with an empty delta (e.g., role-only).
func TestParseSSEChunk_EmptyDelta(t *testing.T) {
	data := []byte(`{"id":"chatcmpl-123","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`)

	chunk, err := ParseSSEChunk(data)
	if err != nil {
		t.Fatalf("ParseSSEChunk() error = %v", err)
	}
	if chunk.Content != "" {
		t.Errorf("Content = %q, want empty for role-only delta", chunk.Content)
	}
}

// TestParseSSEFrame_SingleEvent verifies parsing an SSE frame with a single event.
func TestParseSSEFrame_SingleEvent(t *testing.T) {
	frame := []byte("data: {\"id\":\"chatcmpl-123\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n")

	chunks, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("ParseSSEFrame() returned %d chunks, want 1", len(chunks))
	}
	if chunks[0].Content != "Hello" {
		t.Errorf("chunks[0].Content = %q, want %q", chunks[0].Content, "Hello")
	}
}

// TestParseSSEFrame_MultipleEvents verifies parsing an SSE frame with multiple events in one HTTP frame.
func TestParseSSEFrame_MultipleEvents(t *testing.T) {
	frame := []byte("data: {\"id\":\"chatcmpl-123\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chatcmpl-123\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n\n")

	chunks, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("ParseSSEFrame() returned %d chunks, want 2", len(chunks))
	}
	if chunks[0].Content != "Hello" {
		t.Errorf("chunks[0].Content = %q, want %q", chunks[0].Content, "Hello")
	}
	if chunks[1].Content != " world" {
		t.Errorf("chunks[1].Content = %q, want %q", chunks[1].Content, " world")
	}
}

// TestParseSSEFrame_DoneMarker verifies parsing the [DONE] sentinel marker.
func TestParseSSEFrame_DoneMarker(t *testing.T) {
	frame := []byte("data: [DONE]\n\n")

	chunks, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("ParseSSEFrame() returned %d chunks, want 1", len(chunks))
	}
	if !chunks[0].Done {
		t.Error("chunks[0].Done = false, want true for [DONE] marker")
	}
}

// TestParseSSEFrame_MixedEventsWithDone verifies multi-event frames ending with [DONE].
func TestParseSSEFrame_MixedEventsWithDone(t *testing.T) {
	frame := []byte("data: {\"id\":\"chatcmpl-123\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"!\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")

	chunks, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("ParseSSEFrame() returned %d chunks, want 2", len(chunks))
	}
	if chunks[0].FinishReason != "stop" {
		t.Errorf("chunks[0].FinishReason = %q, want %q", chunks[0].FinishReason, "stop")
	}
	if !chunks[1].Done {
		t.Error("chunks[1].Done = false, want true for [DONE] marker")
	}
}

// TestParseSSEFrame_EmptyFrame verifies parsing an empty or whitespace-only frame.
func TestParseSSEFrame_EmptyFrame(t *testing.T) {
	frame := []byte("")

	chunks, err := ParseSSEFrame(frame)
	if err != nil {
		t.Fatalf("ParseSSEFrame() error = %v", err)
	}
	if len(chunks) != 0 {
		t.Errorf("ParseSSEFrame() returned %d chunks for empty frame, want 0", len(chunks))
	}
}

// --- Non-Streaming Response Parsing Tests ---

// TestParseNonStreamingResponse verifies parsing a complete non-streaming response.
func TestParseNonStreamingResponse(t *testing.T) {
	body := []byte(`{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [
			{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "Hello! How can I help you today?"
				},
				"finish_reason": "stop"
			}
		],
		"usage": {
			"prompt_tokens": 10,
			"completion_tokens": 8,
			"total_tokens": 18
		}
	}`)

	resp, err := ParseNonStreamingResponse(body)
	if err != nil {
		t.Fatalf("ParseNonStreamingResponse() error = %v", err)
	}
	if resp == nil {
		t.Fatal("ParseNonStreamingResponse() returned nil")
	}
	if resp.Content != "Hello! How can I help you today?" {
		t.Errorf("Content = %q, want %q", resp.Content, "Hello! How can I help you today?")
	}
	if resp.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", resp.Model, "gpt-4")
	}
	if resp.FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want %q", resp.FinishReason, "stop")
	}
	if resp.TotalTokens != 18 {
		t.Errorf("TotalTokens = %d, want 18", resp.TotalTokens)
	}
	if resp.InputTokens != 10 {
		t.Errorf("InputTokens = %d, want 10", resp.InputTokens)
	}
	if resp.OutputTokens != 8 {
		t.Errorf("OutputTokens = %d, want 8", resp.OutputTokens)
	}
}
