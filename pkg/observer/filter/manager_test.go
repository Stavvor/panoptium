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

package filter

import (
	"fmt"
	"testing"
)

// mockMapUpdater implements MapUpdater for testing.
type mockMapUpdater struct {
	entries map[string]interface{}
	putErr  error
	delErr  error
}

func newMockMap() *mockMapUpdater {
	return &mockMapUpdater{
		entries: make(map[string]interface{}),
	}
}

func (m *mockMapUpdater) Put(key, value interface{}) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.entries[fmt.Sprintf("%v", key)] = value
	return nil
}

func (m *mockMapUpdater) Delete(key interface{}) error {
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.entries, fmt.Sprintf("%v", key))
	return nil
}

func TestNewFilterManager(t *testing.T) {
	fm := NewFilterManager(newMockMap(), newMockMap(), newMockMap())
	if fm == nil {
		t.Fatal("expected non-nil filter manager")
	}
	if fm.CgroupCount() != 0 {
		t.Errorf("expected 0 cgroups, got %d", fm.CgroupCount())
	}
}

func TestAddRemoveCgroup(t *testing.T) {
	cgMap := newMockMap()
	fm := NewFilterManager(cgMap, nil, nil)

	if err := fm.AddCgroup(100); err != nil {
		t.Fatalf("add cgroup: %v", err)
	}

	if !fm.IsCgroupAllowed(100) {
		t.Error("expected cgroup 100 to be allowed")
	}
	if fm.CgroupCount() != 1 {
		t.Errorf("expected 1 cgroup, got %d", fm.CgroupCount())
	}

	if err := fm.RemoveCgroup(100); err != nil {
		t.Fatalf("remove cgroup: %v", err)
	}

	if fm.IsCgroupAllowed(100) {
		t.Error("expected cgroup 100 to be removed")
	}
	if fm.CgroupCount() != 0 {
		t.Errorf("expected 0 cgroups, got %d", fm.CgroupCount())
	}
}

func TestCgroupNilMap(t *testing.T) {
	fm := NewFilterManager(nil, nil, nil)

	err := fm.AddCgroup(100)
	if err == nil {
		t.Error("expected error with nil cgroup map")
	}

	err = fm.RemoveCgroup(100)
	if err == nil {
		t.Error("expected error with nil cgroup map")
	}
}

func TestCgroupMapError(t *testing.T) {
	cgMap := newMockMap()
	cgMap.putErr = fmt.Errorf("map full")
	fm := NewFilterManager(cgMap, nil, nil)

	err := fm.AddCgroup(100)
	if err == nil {
		t.Error("expected error on map put failure")
	}
}

func TestAddRemovePathPrefix(t *testing.T) {
	pathMap := newMockMap()
	fm := NewFilterManager(nil, pathMap, nil)

	if err := fm.AddPathPrefix("/proc/"); err != nil {
		t.Fatalf("add path prefix: %v", err)
	}
	if fm.PathPrefixCount() != 1 {
		t.Errorf("expected 1 prefix, got %d", fm.PathPrefixCount())
	}

	if err := fm.AddPathPrefix("/sys/"); err != nil {
		t.Fatalf("add path prefix: %v", err)
	}
	if fm.PathPrefixCount() != 2 {
		t.Errorf("expected 2 prefixes, got %d", fm.PathPrefixCount())
	}

	if err := fm.RemovePathPrefix("/proc/"); err != nil {
		t.Fatalf("remove path prefix: %v", err)
	}
	if fm.PathPrefixCount() != 1 {
		t.Errorf("expected 1 prefix after removal, got %d", fm.PathPrefixCount())
	}
}

func TestPathPrefixNilMap(t *testing.T) {
	fm := NewFilterManager(nil, nil, nil)

	err := fm.AddPathPrefix("/proc/")
	if err == nil {
		t.Error("expected error with nil path blocklist map")
	}

	err = fm.RemovePathPrefix("/proc/")
	if err == nil {
		t.Error("expected error with nil path blocklist map")
	}
}

func TestSetRateLimit(t *testing.T) {
	rateMap := newMockMap()
	fm := NewFilterManager(nil, nil, rateMap)

	err := fm.SetRateLimit(100, 1000)
	if err != nil {
		t.Fatalf("set rate limit: %v", err)
	}
}

func TestSetRateLimitNilMap(t *testing.T) {
	fm := NewFilterManager(nil, nil, nil)

	err := fm.SetRateLimit(100, 1000)
	if err == nil {
		t.Error("expected error with nil rate limit map")
	}
}

func TestFilterManagerMultipleCgroups(t *testing.T) {
	cgMap := newMockMap()
	fm := NewFilterManager(cgMap, nil, nil)

	for i := uint64(1); i <= 10; i++ {
		if err := fm.AddCgroup(i); err != nil {
			t.Fatalf("add cgroup %d: %v", i, err)
		}
	}

	if fm.CgroupCount() != 10 {
		t.Errorf("expected 10 cgroups, got %d", fm.CgroupCount())
	}

	// Remove odd cgroups.
	for i := uint64(1); i <= 10; i += 2 {
		if err := fm.RemoveCgroup(i); err != nil {
			t.Fatalf("remove cgroup %d: %v", i, err)
		}
	}

	if fm.CgroupCount() != 5 {
		t.Errorf("expected 5 cgroups, got %d", fm.CgroupCount())
	}
}

func TestRemoveCgroupMapError(t *testing.T) {
	cgMap := newMockMap()
	fm := NewFilterManager(cgMap, nil, nil)

	// Add first.
	if err := fm.AddCgroup(100); err != nil {
		t.Fatal(err)
	}

	// Simulate map error on delete.
	cgMap.delErr = fmt.Errorf("permission denied")
	err := fm.RemoveCgroup(100)
	if err == nil {
		t.Error("expected error on map delete failure")
	}
}
