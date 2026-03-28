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

// Package openai provides parsing logic for OpenAI API request and response formats.
package openai

// ChatCompletionRequest represents a parsed OpenAI chat completion request.
type ChatCompletionRequest struct {
	// Model is the model identifier (e.g., "gpt-4", "gpt-3.5-turbo").
	Model string

	// Messages contains the conversation messages.
	Messages []Message

	// Stream indicates whether streaming is enabled.
	Stream bool
}

// Message represents a single message in a chat completion request.
type Message struct {
	// Role is the message role (e.g., "system", "user", "assistant").
	Role string

	// Content is the message text content.
	Content string
}

// StreamChunk represents a parsed SSE chunk from a streaming response.
type StreamChunk struct {
	// ID is the chunk identifier.
	ID string

	// Content is the token text content from this chunk.
	Content string

	// FinishReason is set on the final chunk (e.g., "stop", "length").
	FinishReason string

	// Done indicates this is the [DONE] sentinel.
	Done bool
}

// ParseRequest parses a raw JSON request body into a ChatCompletionRequest.
func ParseRequest(body []byte) (*ChatCompletionRequest, error) {
	return nil, nil
}

// ParseSSEChunk parses a single SSE data line into a StreamChunk.
func ParseSSEChunk(data []byte) (*StreamChunk, error) {
	return nil, nil
}

// ParseSSEFrame parses a raw HTTP frame that may contain multiple SSE events.
// Returns a slice of StreamChunks, one per event in the frame.
func ParseSSEFrame(frame []byte) ([]*StreamChunk, error) {
	return nil, nil
}

// ParseResponse parses a non-streaming JSON response body.
type ChatCompletionResponse struct {
	// Content is the full response text.
	Content string

	// Model is the model used.
	Model string

	// FinishReason is the reason generation stopped.
	FinishReason string

	// TotalTokens is the total token count reported by the API.
	TotalTokens int

	// InputTokens is the prompt token count.
	InputTokens int

	// OutputTokens is the completion token count.
	OutputTokens int
}

// ParseNonStreamingResponse parses a complete non-streaming response body.
func ParseNonStreamingResponse(body []byte) (*ChatCompletionResponse, error) {
	return nil, nil
}
