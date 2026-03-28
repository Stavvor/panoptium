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

// Package anthropic provides parsing logic for Anthropic API request and response formats.
package anthropic

// MessagesRequest represents a parsed Anthropic messages API request.
type MessagesRequest struct {
	// Model is the model identifier (e.g., "claude-3-opus-20240229").
	Model string

	// Messages contains the conversation messages.
	Messages []Message

	// Stream indicates whether streaming is enabled.
	Stream bool

	// MaxTokens is the maximum number of tokens to generate.
	MaxTokens int
}

// Message represents a single message in a messages API request.
type Message struct {
	// Role is the message role ("user" or "assistant").
	Role string

	// Content is the message text content.
	Content string
}

// StreamEvent represents a parsed SSE event from a streaming response.
type StreamEvent struct {
	// EventType is the SSE event type (e.g., "content_block_delta", "message_stop").
	EventType string

	// Content is the token text content (for content_block_delta events).
	Content string

	// Done indicates this is a terminal event (message_stop).
	Done bool

	// StopReason is the reason generation stopped (for message_stop events).
	StopReason string
}

// ParseRequest parses a raw JSON request body into a MessagesRequest.
func ParseRequest(body []byte) (*MessagesRequest, error) {
	return nil, nil
}

// ParseSSEEvent parses a single SSE event (event line + data line) into a StreamEvent.
func ParseSSEEvent(eventType string, data []byte) (*StreamEvent, error) {
	return nil, nil
}

// ParseSSEFrame parses a raw HTTP frame that may contain multiple SSE events.
// Returns a slice of StreamEvents.
func ParseSSEFrame(frame []byte) ([]*StreamEvent, error) {
	return nil, nil
}

// MessagesResponse represents a parsed non-streaming Anthropic response.
type MessagesResponse struct {
	// Content is the full response text.
	Content string

	// Model is the model used.
	Model string

	// StopReason is the reason generation stopped.
	StopReason string

	// InputTokens is the input token count.
	InputTokens int

	// OutputTokens is the output token count.
	OutputTokens int
}

// ParseNonStreamingResponse parses a complete non-streaming response body.
func ParseNonStreamingResponse(body []byte) (*MessagesResponse, error) {
	return nil, nil
}
