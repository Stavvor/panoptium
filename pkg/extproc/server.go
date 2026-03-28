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

// Package extproc implements an Envoy External Processing (ExtProc) gRPC server
// that passively observes LLM token streams flowing through AgentGateway.
package extproc

import (
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
)

// ExtProcServer implements the Envoy ExternalProcessor gRPC service.
// It passively observes LLM traffic flowing through AgentGateway by
// delegating to the ObserverRegistry for protocol-specific parsing
// and publishing events via the EventBus.
type ExtProcServer struct {
	extprocv3.UnimplementedExternalProcessorServer

	registry *observer.ObserverRegistry
	resolver *identity.Resolver
	bus      eventbus.EventBus
}

// NewExtProcServer creates a new ExtProcServer with the given dependencies.
func NewExtProcServer(registry *observer.ObserverRegistry, resolver *identity.Resolver, bus eventbus.EventBus) *ExtProcServer {
	return &ExtProcServer{
		registry: registry,
		resolver: resolver,
		bus:      bus,
	}
}
