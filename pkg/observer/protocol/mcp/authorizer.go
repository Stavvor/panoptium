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

package mcp

import (
	"fmt"
	"path/filepath"
	"sync"
)

// AuthorizationResult contains the result of a tool authorization check.
type AuthorizationResult struct {
	// ToolName is the name of the tool that was checked.
	ToolName string

	// Allowed indicates whether the tool call is authorized.
	Allowed bool

	// Reason describes why the tool was allowed or denied.
	Reason string
}

// MCPToolAuthorizer evaluates tool call authorization against configured
// allow/deny patterns. Deny patterns take precedence over allow patterns.
// If no allow patterns are configured, default policy is deny-all.
type MCPToolAuthorizer struct {
	mu            sync.RWMutex
	allowPatterns []string
	denyPatterns  []string
}

// NewMCPToolAuthorizer creates a new tool authorizer with no patterns (default deny).
func NewMCPToolAuthorizer() *MCPToolAuthorizer {
	return &MCPToolAuthorizer{
		allowPatterns: make([]string, 0),
		denyPatterns:  make([]string, 0),
	}
}

// AddAllowPattern adds a glob pattern to the allow list.
// Supports * and ? wildcards (e.g., "fs_*" matches "fs_read", "fs_write").
func (a *MCPToolAuthorizer) AddAllowPattern(pattern string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowPatterns = append(a.allowPatterns, pattern)
}

// AddDenyPattern adds a glob pattern to the deny list.
// Deny patterns take precedence over allow patterns.
func (a *MCPToolAuthorizer) AddDenyPattern(pattern string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.denyPatterns = append(a.denyPatterns, pattern)
}

// Authorize checks whether a tool name is authorized based on configured
// allow/deny patterns. Deny patterns take precedence.
func (a *MCPToolAuthorizer) Authorize(toolName string) AuthorizationResult {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := AuthorizationResult{
		ToolName: toolName,
	}

	// Check deny patterns first (deny takes precedence)
	for _, pattern := range a.denyPatterns {
		matched, _ := filepath.Match(pattern, toolName)
		if matched {
			result.Allowed = false
			result.Reason = fmt.Sprintf("tool %q matches deny pattern %q", toolName, pattern)
			return result
		}
	}

	// Check allow patterns
	if len(a.allowPatterns) == 0 {
		result.Allowed = false
		result.Reason = fmt.Sprintf("tool %q denied: no allow patterns configured", toolName)
		return result
	}

	for _, pattern := range a.allowPatterns {
		matched, _ := filepath.Match(pattern, toolName)
		if matched {
			result.Allowed = true
			result.Reason = fmt.Sprintf("tool %q matches allow pattern %q", toolName, pattern)
			return result
		}
	}

	result.Allowed = false
	result.Reason = fmt.Sprintf("tool %q does not match any allow pattern", toolName)
	return result
}
