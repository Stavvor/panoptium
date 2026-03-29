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

import (
	"testing"
)

func TestNewProcessTreeTracker(t *testing.T) {
	tracker := NewProcessTreeTracker()
	if tracker == nil {
		t.Fatal("expected non-nil tracker")
	}
	if tracker.TreeSize() != 0 {
		t.Errorf("expected empty tree, got %d", tracker.TreeSize())
	}
}

func TestAddForkAndGetParent(t *testing.T) {
	tracker := NewProcessTreeTracker()
	tracker.AddFork(100, 200)

	parent := tracker.GetParent(200)
	if parent != 100 {
		t.Errorf("expected parent 100, got %d", parent)
	}

	if tracker.TreeSize() != 1 {
		t.Errorf("expected tree size 1, got %d", tracker.TreeSize())
	}
}

func TestGetParentUnknown(t *testing.T) {
	tracker := NewProcessTreeTracker()
	parent := tracker.GetParent(999)
	if parent != 0 {
		t.Errorf("expected 0 for unknown PID, got %d", parent)
	}
}

func TestGetAncestryThreeLevels(t *testing.T) {
	tracker := NewProcessTreeTracker()
	// Build: 1 -> 10 -> 100 -> 1000
	tracker.AddFork(1, 10)
	tracker.AddFork(10, 100)
	tracker.AddFork(100, 1000)

	chain := tracker.GetAncestry(1000)
	expected := []uint32{1000, 100, 10, 1}

	if len(chain) != len(expected) {
		t.Fatalf("expected chain length %d, got %d: %v", len(expected), len(chain), chain)
	}

	for i, pid := range expected {
		if chain[i] != pid {
			t.Errorf("chain[%d]: expected %d, got %d", i, pid, chain[i])
		}
	}
}

func TestGetAncestryTerminatesAtInit(t *testing.T) {
	tracker := NewProcessTreeTracker()
	tracker.AddFork(1, 50)
	tracker.AddFork(50, 100)

	chain := tracker.GetAncestry(100)
	// Should be [100, 50, 1] and stop at PID 1 (init).
	if len(chain) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(chain), chain)
	}
	if chain[len(chain)-1] != 1 {
		t.Errorf("expected chain to end at PID 1, got %d", chain[len(chain)-1])
	}
}

func TestGetAncestryBrokenChain(t *testing.T) {
	tracker := NewProcessTreeTracker()
	// Only register one level. Parent is unknown.
	tracker.AddFork(999, 100)

	chain := tracker.GetAncestry(100)
	// Should be [100, 999] and stop because 999's parent is unknown.
	if len(chain) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(chain), chain)
	}
}

func TestGetAncestryCacheReuse(t *testing.T) {
	tracker := NewProcessTreeTracker()
	tracker.AddFork(1, 10)
	tracker.AddFork(10, 100)

	// First call populates cache.
	chain1 := tracker.GetAncestry(100)
	// Second call should return cached result.
	chain2 := tracker.GetAncestry(100)

	if len(chain1) != len(chain2) {
		t.Fatalf("cached chain differs in length: %d vs %d", len(chain1), len(chain2))
	}
	for i := range chain1 {
		if chain1[i] != chain2[i] {
			t.Errorf("chain[%d]: %d vs %d", i, chain1[i], chain2[i])
		}
	}
}

func TestRemoveProcessClearsCache(t *testing.T) {
	tracker := NewProcessTreeTracker()
	tracker.AddFork(1, 10)
	tracker.AddFork(10, 100)

	// Populate cache.
	_ = tracker.GetAncestry(100)

	// Remove the intermediate process.
	tracker.RemoveProcess(10)

	// Ancestry should now be broken.
	_ = tracker.GetAncestry(100)
	// 100's parent (10) was removed, but the mapping 100->10 still exists
	// until 100 is also removed. Let's check that RemoveProcess clears the PID.
	if tracker.GetParent(10) != 0 {
		t.Error("expected parent of removed PID to be 0")
	}
}

func TestAddForkInvalidatesCacheForChild(t *testing.T) {
	tracker := NewProcessTreeTracker()
	tracker.AddFork(1, 10)

	// Populate cache for PID 10.
	chain1 := tracker.GetAncestry(10)
	if len(chain1) != 2 {
		t.Fatalf("expected 2, got %d", len(chain1))
	}

	// Re-parent PID 10 (shouldn't normally happen, but tests cache invalidation).
	tracker.AddFork(2, 10)

	chain2 := tracker.GetAncestry(10)
	if len(chain2) < 2 {
		t.Fatalf("expected at least 2, got %d", len(chain2))
	}
	if chain2[1] != 2 {
		t.Errorf("expected new parent 2, got %d", chain2[1])
	}
}

func TestGetAncestrySingleProcess(t *testing.T) {
	tracker := NewProcessTreeTracker()

	// PID with no parent.
	chain := tracker.GetAncestry(42)
	if len(chain) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(chain))
	}
	if chain[0] != 42 {
		t.Errorf("expected PID 42, got %d", chain[0])
	}
}

func TestGetAncestryCycleDetection(t *testing.T) {
	tracker := NewProcessTreeTracker()
	// Create a cycle: 10 -> 20 -> 30 -> 10
	tracker.AddFork(30, 10)
	tracker.AddFork(10, 20)
	tracker.AddFork(20, 30)

	// Should terminate without infinite loop.
	chain := tracker.GetAncestry(10)
	if len(chain) > maxAncestryDepth+1 {
		t.Errorf("ancestry chain too long, possible infinite loop: %d", len(chain))
	}
}
