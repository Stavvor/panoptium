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

package observer

import (
	"context"
	"errors"
)

// ErrDuplicateObserver is returned when attempting to register an observer
// with a name that is already registered.
var ErrDuplicateObserver = errors.New("observer with this name is already registered")

// ErrNoMatchingObserver is returned when no registered observer can handle
// the given request context.
var ErrNoMatchingObserver = errors.New("no observer can handle this request")

// ObserverRegistry manages a set of ProtocolObservers and routes requests
// to the appropriate observer based on priority and confidence scoring.
type ObserverRegistry struct{}

// NewObserverRegistry creates a new ObserverRegistry.
func NewObserverRegistry() *ObserverRegistry {
	return &ObserverRegistry{}
}

// Register adds a ProtocolObserver to the registry with the given configuration.
// Returns ErrDuplicateObserver if an observer with the same name is already registered.
func (r *ObserverRegistry) Register(observer ProtocolObserver, config ObserverConfig) error {
	return nil
}

// Unregister removes a ProtocolObserver from the registry by name.
// Returns false if no observer with the given name was found.
func (r *ObserverRegistry) Unregister(name string) bool {
	return false
}

// SelectObserver finds the best matching observer for the given request context.
// Observers are consulted in priority order; the one with the highest confidence
// score that can handle the request is selected.
// Returns ErrNoMatchingObserver if no registered observer can handle the request.
func (r *ObserverRegistry) SelectObserver(ctx context.Context, req *ObserverContext) (ProtocolObserver, error) {
	return nil, ErrNoMatchingObserver
}

// Observers returns a list of all registered observer names, in priority order.
func (r *ObserverRegistry) Observers() []string {
	return nil
}
