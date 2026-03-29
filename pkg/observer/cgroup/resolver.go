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

// Package cgroup provides cgroup ID to Kubernetes pod identity resolution
// for the eBPF observer.
package cgroup

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// PodIdentity contains the resolved Kubernetes pod identity for a cgroup.
type PodIdentity struct {
	// PodName is the Kubernetes pod name.
	PodName string

	// Namespace is the Kubernetes namespace.
	Namespace string

	// ContainerID is the container runtime ID (e.g., containerd://...).
	ContainerID string

	// Labels contains the Kubernetes labels of the pod.
	Labels map[string]string
}

// PodInformer is an interface for resolving container IDs to pod identities.
// In production this is backed by a Kubernetes informer cache.
type PodInformer interface {
	// GetPodByContainerID resolves a container ID to its pod identity.
	// Returns nil if the container ID is not found.
	GetPodByContainerID(containerID string) *PodIdentity
}

// cacheEntry holds a cached cgroup-to-pod resolution.
type cacheEntry struct {
	identity  *PodIdentity
	timestamp time.Time
}

// CgroupResolver maps eBPF cgroup IDs to Kubernetes pod identities.
// It uses a two-step resolution: cgroup ID -> container ID (via cgroup filesystem)
// and container ID -> pod identity (via Kubernetes informer cache).
type CgroupResolver struct {
	mu sync.RWMutex

	// cache maps cgroup IDs to resolved pod identities.
	cache map[uint64]*cacheEntry

	// containerMap maps cgroup IDs to container IDs (populated from cgroup fs).
	containerMap map[uint64]string

	// informer provides container ID -> pod identity resolution.
	informer PodInformer

	// maxCacheSize is the maximum number of entries in the LRU cache.
	maxCacheSize int

	// cgroupBasePath is the base path for the cgroup filesystem.
	cgroupBasePath string
}

// ResolverOption configures the CgroupResolver.
type ResolverOption func(*CgroupResolver)

// WithMaxCacheSize sets the maximum LRU cache size.
func WithMaxCacheSize(size int) ResolverOption {
	return func(r *CgroupResolver) {
		r.maxCacheSize = size
	}
}

// WithCgroupBasePath sets the cgroup filesystem base path.
func WithCgroupBasePath(path string) ResolverOption {
	return func(r *CgroupResolver) {
		r.cgroupBasePath = path
	}
}

// NewCgroupResolver creates a new CgroupResolver with the given PodInformer.
func NewCgroupResolver(informer PodInformer, opts ...ResolverOption) *CgroupResolver {
	r := &CgroupResolver{
		cache:          make(map[uint64]*cacheEntry),
		containerMap:   make(map[uint64]string),
		informer:       informer,
		maxCacheSize:   4096,
		cgroupBasePath: "/sys/fs/cgroup",
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve maps a cgroup ID to a PodIdentity.
// Returns nil if the cgroup ID cannot be resolved to a known pod.
// Cached lookups return within 1ms (per FR-4).
func (r *CgroupResolver) Resolve(cgroupID uint64) *PodIdentity {
	// Fast path: check cache.
	r.mu.RLock()
	if entry, ok := r.cache[cgroupID]; ok {
		r.mu.RUnlock()
		return entry.identity
	}
	r.mu.RUnlock()

	// Slow path: resolve from container map and informer.
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if entry, ok := r.cache[cgroupID]; ok {
		return entry.identity
	}

	// Step 1: cgroup ID -> container ID.
	containerID, ok := r.containerMap[cgroupID]
	if !ok {
		return nil
	}

	// Step 2: container ID -> pod identity.
	if r.informer == nil {
		return nil
	}

	identity := r.informer.GetPodByContainerID(containerID)
	if identity == nil {
		return nil
	}

	// Cache the result.
	r.evictIfNeeded()
	r.cache[cgroupID] = &cacheEntry{
		identity:  identity,
		timestamp: time.Now(),
	}

	return identity
}

// RegisterContainer maps a cgroup ID to a container ID.
// Called when a new container is detected (e.g., from pod informer events).
func (r *CgroupResolver) RegisterContainer(cgroupID uint64, containerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.containerMap[cgroupID] = containerID
	slog.Debug("registered container",
		"cgroup_id", cgroupID,
		"container_id", containerID,
	)
}

// UnregisterContainer removes a cgroup ID mapping.
// Called when a container/pod is deleted.
func (r *CgroupResolver) UnregisterContainer(cgroupID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.containerMap, cgroupID)
	delete(r.cache, cgroupID)
}

// CacheSize returns the current number of entries in the cache.
func (r *CgroupResolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

// evictIfNeeded removes the oldest cache entry if the cache is at capacity.
// Must be called with r.mu held.
func (r *CgroupResolver) evictIfNeeded() {
	if len(r.cache) < r.maxCacheSize {
		return
	}

	// Find and remove the oldest entry.
	var oldestKey uint64
	var oldestTime time.Time
	first := true

	for k, v := range r.cache {
		if first || v.timestamp.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.timestamp
			first = false
		}
	}

	if !first {
		delete(r.cache, oldestKey)
		slog.Debug("evicted cache entry",
			"cgroup_id", oldestKey,
		)
	}
}

// String returns a human-readable summary of the resolver state.
func (r *CgroupResolver) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return fmt.Sprintf("CgroupResolver{cache=%d, containers=%d, max=%d}",
		len(r.cache), len(r.containerMap), r.maxCacheSize)
}
