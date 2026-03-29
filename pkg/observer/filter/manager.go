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

// Package filter provides in-kernel pre-filtering configuration for eBPF programs.
// It manages BPF map updates for cgroup allowlists, path blocklists, and rate limits.
package filter

import (
	"fmt"
	"log/slog"
	"sync"
)

// MapUpdater is an interface for updating BPF maps from userspace.
// In production this is backed by cilium/ebpf Map instances.
type MapUpdater interface {
	// Put adds or updates a key-value pair in the BPF map.
	Put(key, value interface{}) error

	// Delete removes a key from the BPF map.
	Delete(key interface{}) error
}

// FilterManager manages in-kernel pre-filter BPF maps for event volume reduction.
// It configures cgroup allowlists, path prefix blocklists, and per-cgroup rate limits.
type FilterManager struct {
	mu sync.Mutex

	// cgroupMap is the BPF cgroup allowlist map.
	cgroupMap MapUpdater

	// pathBlocklistMap is the BPF path prefix blocklist map (LPM trie).
	pathBlocklistMap MapUpdater

	// rateLimitMap is the BPF per-cgroup rate limit map.
	rateLimitMap MapUpdater

	// cgroups tracks registered cgroup IDs for bookkeeping.
	cgroups map[uint64]bool

	// pathPrefixes tracks registered path prefixes.
	pathPrefixes map[string]bool
}

// NewFilterManager creates a new FilterManager with the given BPF map updaters.
// Any map may be nil if that filter type is not available.
func NewFilterManager(cgroupMap, pathBlocklistMap, rateLimitMap MapUpdater) *FilterManager {
	return &FilterManager{
		cgroupMap:        cgroupMap,
		pathBlocklistMap: pathBlocklistMap,
		rateLimitMap:     rateLimitMap,
		cgroups:          make(map[uint64]bool),
		pathPrefixes:     make(map[string]bool),
	}
}

// AddCgroup adds a cgroup ID to the allowlist.
// Only events from allowed cgroups will be emitted by eBPF programs.
func (m *FilterManager) AddCgroup(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cgroupMap == nil {
		return fmt.Errorf("cgroup map not configured")
	}

	val := uint8(1)
	if err := m.cgroupMap.Put(cgroupID, val); err != nil {
		return fmt.Errorf("add cgroup %d: %w", cgroupID, err)
	}

	m.cgroups[cgroupID] = true
	slog.Debug("added cgroup to allowlist", "cgroup_id", cgroupID)
	return nil
}

// RemoveCgroup removes a cgroup ID from the allowlist.
func (m *FilterManager) RemoveCgroup(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cgroupMap == nil {
		return fmt.Errorf("cgroup map not configured")
	}

	if err := m.cgroupMap.Delete(cgroupID); err != nil {
		return fmt.Errorf("remove cgroup %d: %w", cgroupID, err)
	}

	delete(m.cgroups, cgroupID)
	slog.Debug("removed cgroup from allowlist", "cgroup_id", cgroupID)
	return nil
}

// pathPrefixKey matches the C struct path_prefix_key used in the LPM trie.
type pathPrefixKey struct {
	PrefixLen uint32
	Data      [256]byte
}

// AddPathPrefix adds a path prefix to the blocklist.
// openat events matching this prefix will be suppressed in-kernel.
func (m *FilterManager) AddPathPrefix(prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pathBlocklistMap == nil {
		return fmt.Errorf("path blocklist map not configured")
	}

	key := pathPrefixKey{
		PrefixLen: uint32(len(prefix) * 8),
	}
	copy(key.Data[:], prefix)

	val := uint8(1)
	if err := m.pathBlocklistMap.Put(key, val); err != nil {
		return fmt.Errorf("add path prefix %q: %w", prefix, err)
	}

	m.pathPrefixes[prefix] = true
	slog.Debug("added path prefix to blocklist", "prefix", prefix)
	return nil
}

// RemovePathPrefix removes a path prefix from the blocklist.
func (m *FilterManager) RemovePathPrefix(prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pathBlocklistMap == nil {
		return fmt.Errorf("path blocklist map not configured")
	}

	key := pathPrefixKey{
		PrefixLen: uint32(len(prefix) * 8),
	}
	copy(key.Data[:], prefix)

	if err := m.pathBlocklistMap.Delete(key); err != nil {
		return fmt.Errorf("remove path prefix %q: %w", prefix, err)
	}

	delete(m.pathPrefixes, prefix)
	slog.Debug("removed path prefix from blocklist", "prefix", prefix)
	return nil
}

// rateLimitValue matches the BPF map value for rate limiting.
type rateLimitValue struct {
	MaxPerSec uint32
}

// SetRateLimit sets the per-cgroup event rate limit.
func (m *FilterManager) SetRateLimit(cgroupID uint64, maxPerSec uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.rateLimitMap == nil {
		return fmt.Errorf("rate limit map not configured")
	}

	val := rateLimitValue{MaxPerSec: maxPerSec}
	if err := m.rateLimitMap.Put(cgroupID, val); err != nil {
		return fmt.Errorf("set rate limit for cgroup %d: %w", cgroupID, err)
	}

	slog.Debug("set rate limit", "cgroup_id", cgroupID, "max_per_sec", maxPerSec)
	return nil
}

// CgroupCount returns the number of cgroups in the allowlist.
func (m *FilterManager) CgroupCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cgroups)
}

// PathPrefixCount returns the number of path prefixes in the blocklist.
func (m *FilterManager) PathPrefixCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pathPrefixes)
}

// IsCgroupAllowed returns whether a cgroup ID is in the allowlist.
func (m *FilterManager) IsCgroupAllowed(cgroupID uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cgroups[cgroupID]
}
