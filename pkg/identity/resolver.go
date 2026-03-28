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

// Package identity provides agent identity resolution for the Panoptium operator.
// It extracts agent identity from x-panoptium-* headers injected by AgentGateway
// and resolves pod information via a Kubernetes-backed IP cache.
package identity

import (
	"net/http"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

// Header constants for x-panoptium-* headers injected by AgentGateway.
const (
	// HeaderAgentID is the primary agent identifier header.
	HeaderAgentID = "X-Panoptium-Agent-Id"

	// HeaderClientIP is the source pod IP header.
	HeaderClientIP = "X-Panoptium-Client-Ip"

	// HeaderAuthType is the authentication type header ("jwt" or "source-ip").
	HeaderAuthType = "X-Panoptium-Auth-Type"

	// HeaderRequestID is the unique request correlation ID header.
	HeaderRequestID = "X-Panoptium-Request-Id"
)

// Resolver resolves agent identity from HTTP headers using cascading lookup.
type Resolver struct {
	cache *PodCache
}

// NewResolver creates a new Resolver with the given pod IP cache.
// The cache may be nil if pod resolution is not needed.
func NewResolver(cache *PodCache) *Resolver {
	return &Resolver{cache: cache}
}

// Resolve extracts agent identity from the provided HTTP headers.
// TODO: implement cascading resolution logic.
func (r *Resolver) Resolve(headers http.Header) eventbus.AgentIdentity {
	return eventbus.AgentIdentity{}
}
