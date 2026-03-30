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

package cgroup

import "sync"

// maxAncestryDepth limits the ancestry chain to prevent infinite loops.
const maxAncestryDepth = 32

// ProcessTreeTracker maintains a PID -> parent PID mapping for process
// ancestry chain reconstruction. The map is populated from Tetragon
// ProcessExec events (which include parent info) and cleaned up on
// ProcessExit events.
type ProcessTreeTracker struct {
	mu sync.RWMutex
	// tree maps child PID to parent PID.
	tree map[uint32]uint32
	// ancestryCache caches resolved ancestry chains.
	ancestryCache map[uint32][]uint32
}

// NewProcessTreeTracker creates a new ProcessTreeTracker.
func NewProcessTreeTracker() *ProcessTreeTracker {
	return &ProcessTreeTracker{
		tree:          make(map[uint32]uint32),
		ancestryCache: make(map[uint32][]uint32),
	}
}

// AddFork records a parent-child PID relationship.
// Called from fork event processing.
func (t *ProcessTreeTracker) AddFork(parentPID, childPID uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.tree[childPID] = parentPID
	// Invalidate ancestry cache for the child.
	delete(t.ancestryCache, childPID)
}

// RemoveProcess removes a PID from the tree (e.g., on process exit).
func (t *ProcessTreeTracker) RemoveProcess(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.tree, pid)
	delete(t.ancestryCache, pid)
}

// GetAncestry returns the process ancestry chain for the given PID.
// The chain starts with the given PID and walks up to PID 1 (init)
// or until the chain is broken (unknown parent).
// Results are cached for repeated lookups.
func (t *ProcessTreeTracker) GetAncestry(pid uint32) []uint32 {
	t.mu.RLock()
	if cached, ok := t.ancestryCache[pid]; ok {
		t.mu.RUnlock()
		return cached
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Double-check after acquiring write lock.
	if cached, ok := t.ancestryCache[pid]; ok {
		return cached
	}

	chain := t.walkAncestry(pid)
	t.ancestryCache[pid] = chain
	return chain
}

// walkAncestry traverses the process tree from pid to root.
// Must be called with t.mu held.
func (t *ProcessTreeTracker) walkAncestry(pid uint32) []uint32 {
	chain := []uint32{pid}
	current := pid
	visited := make(map[uint32]bool)
	visited[pid] = true

	for i := 0; i < maxAncestryDepth; i++ {
		parent, ok := t.tree[current]
		if !ok || parent == 0 {
			break
		}

		// Detect cycles.
		if visited[parent] {
			break
		}

		chain = append(chain, parent)
		visited[parent] = true

		// Stop at init (PID 1).
		if parent == 1 {
			break
		}

		current = parent
	}

	return chain
}

// TreeSize returns the number of PIDs tracked.
func (t *ProcessTreeTracker) TreeSize() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.tree)
}

// GetParent returns the parent PID for the given PID, or 0 if unknown.
func (t *ProcessTreeTracker) GetParent(pid uint32) uint32 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.tree[pid]
}

// maxTetragonAncestryDepth limits how many levels of Tetragon parent chain to ingest.
const maxTetragonAncestryDepth = 5

// TetragonProcessInfo holds process information from a Tetragon event.
// This provides a clean interface without importing the Tetragon package.
type TetragonProcessInfo struct {
	// PID of the process.
	PID uint32
	// ParentPID of the process.
	ParentPID uint32
	// AncestorPIDs is the chain of ancestor PIDs from Tetragon's parent field.
	// Index 0 is the grandparent, index 1 is the great-grandparent, etc.
	AncestorPIDs []uint32
}

// HandleProcessExec ingests a Tetragon ProcessExec event to build ancestry.
// It records the process's parent relationship and optionally ingests
// the ancestor chain up to maxTetragonAncestryDepth levels.
func (t *ProcessTreeTracker) HandleProcessExec(info TetragonProcessInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if info.ParentPID != 0 {
		t.tree[info.PID] = info.ParentPID
		delete(t.ancestryCache, info.PID)
	}

	// Ingest ancestor chain from Tetragon's parent field.
	current := info.ParentPID
	for i, ancestor := range info.AncestorPIDs {
		if i >= maxTetragonAncestryDepth || current == 0 || ancestor == 0 {
			break
		}
		if _, exists := t.tree[current]; !exists {
			t.tree[current] = ancestor
			delete(t.ancestryCache, current)
		}
		current = ancestor
	}
}

// HandleProcessExit cleans up the process tree when a process exits.
// This prevents unbounded growth of the tree map.
func (t *ProcessTreeTracker) HandleProcessExit(pid uint32) {
	t.RemoveProcess(pid)
}
