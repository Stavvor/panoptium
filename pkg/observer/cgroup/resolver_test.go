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
	"time"
)

// mockInformer implements PodInformer for testing.
type mockInformer struct {
	pods map[string]*PodIdentity
}

func (m *mockInformer) GetPodByContainerID(containerID string) *PodIdentity {
	return m.pods[containerID]
}

func newMockInformer() *mockInformer {
	return &mockInformer{
		pods: make(map[string]*PodIdentity),
	}
}

func TestNewCgroupResolver(t *testing.T) {
	informer := newMockInformer()
	resolver := NewCgroupResolver(informer)

	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
	if resolver.CacheSize() != 0 {
		t.Errorf("expected empty cache, got %d", resolver.CacheSize())
	}
}

func TestResolverWithOptions(t *testing.T) {
	informer := newMockInformer()
	resolver := NewCgroupResolver(informer,
		WithMaxCacheSize(128),
		WithCgroupBasePath("/test/cgroup"),
	)

	if resolver.maxCacheSize != 128 {
		t.Errorf("expected maxCacheSize=128, got %d", resolver.maxCacheSize)
	}
	if resolver.cgroupBasePath != "/test/cgroup" {
		t.Errorf("expected cgroupBasePath=/test/cgroup, got %q", resolver.cgroupBasePath)
	}
}

func TestResolveUnknownCgroup(t *testing.T) {
	informer := newMockInformer()
	resolver := NewCgroupResolver(informer)

	identity := resolver.Resolve(42)
	if identity != nil {
		t.Error("expected nil for unknown cgroup ID")
	}
}

func TestResolveRegisteredContainer(t *testing.T) {
	informer := newMockInformer()
	informer.pods["abc123"] = &PodIdentity{
		PodName:     "test-pod",
		Namespace:   "default",
		ContainerID: "abc123",
		Labels:      map[string]string{"app": "test"},
	}

	resolver := NewCgroupResolver(informer)
	resolver.RegisterContainer(100, "abc123")

	identity := resolver.Resolve(100)
	if identity == nil {
		t.Fatal("expected non-nil identity")
	}
	if identity.PodName != "test-pod" {
		t.Errorf("expected pod name test-pod, got %q", identity.PodName)
	}
	if identity.Namespace != "default" {
		t.Errorf("expected namespace default, got %q", identity.Namespace)
	}
}

func TestResolveCacheHit(t *testing.T) {
	informer := newMockInformer()
	informer.pods["abc123"] = &PodIdentity{
		PodName:   "test-pod",
		Namespace: "default",
	}

	resolver := NewCgroupResolver(informer)
	resolver.RegisterContainer(100, "abc123")

	// First call populates cache.
	identity1 := resolver.Resolve(100)
	if identity1 == nil {
		t.Fatal("first resolve: expected non-nil")
	}

	// Measure cache hit performance.
	start := time.Now()
	for i := 0; i < 10000; i++ {
		resolver.Resolve(100)
	}
	elapsed := time.Since(start)

	// 10000 cached lookups should complete well within 1 second.
	// Per FR-4: cached lookups must complete within 1ms each.
	if elapsed > 1*time.Second {
		t.Errorf("10000 cached lookups took %v, expected <1s", elapsed)
	}

	if resolver.CacheSize() != 1 {
		t.Errorf("expected cache size 1, got %d", resolver.CacheSize())
	}
}

func TestResolveCacheMissThenHit(t *testing.T) {
	informer := newMockInformer()
	resolver := NewCgroupResolver(informer)
	resolver.RegisterContainer(100, "abc123")

	// Resolve when informer has no entry yet.
	identity := resolver.Resolve(100)
	if identity != nil {
		t.Error("expected nil before informer populated")
	}

	// Now populate the informer.
	informer.pods["abc123"] = &PodIdentity{
		PodName:   "late-pod",
		Namespace: "system",
	}

	// Resolve again - should find it now.
	identity = resolver.Resolve(100)
	if identity == nil {
		t.Fatal("expected non-nil after informer populated")
	}
	if identity.PodName != "late-pod" {
		t.Errorf("expected late-pod, got %q", identity.PodName)
	}
}

func TestUnregisterContainer(t *testing.T) {
	informer := newMockInformer()
	informer.pods["abc123"] = &PodIdentity{
		PodName:   "test-pod",
		Namespace: "default",
	}

	resolver := NewCgroupResolver(informer)
	resolver.RegisterContainer(100, "abc123")

	// Resolve to populate cache.
	identity := resolver.Resolve(100)
	if identity == nil {
		t.Fatal("expected non-nil before unregister")
	}

	// Unregister.
	resolver.UnregisterContainer(100)

	// Should no longer resolve.
	identity = resolver.Resolve(100)
	if identity != nil {
		t.Error("expected nil after unregister")
	}

	if resolver.CacheSize() != 0 {
		t.Errorf("expected empty cache after unregister, got %d", resolver.CacheSize())
	}
}

func TestCacheEviction(t *testing.T) {
	informer := newMockInformer()
	resolver := NewCgroupResolver(informer, WithMaxCacheSize(3))

	// Register and resolve 4 containers.
	for i := uint64(1); i <= 4; i++ {
		containerID := "container-" + string(rune('a'+i-1))
		informer.pods[containerID] = &PodIdentity{
			PodName:   "pod-" + string(rune('a'+i-1)),
			Namespace: "default",
		}
		resolver.RegisterContainer(i, containerID)
		resolver.Resolve(i)
	}

	// Cache should be at most maxCacheSize.
	if resolver.CacheSize() > 3 {
		t.Errorf("expected cache size <= 3, got %d", resolver.CacheSize())
	}
}

func TestResolverString(t *testing.T) {
	informer := newMockInformer()
	resolver := NewCgroupResolver(informer, WithMaxCacheSize(100))

	s := resolver.String()
	if s == "" {
		t.Error("expected non-empty string representation")
	}
}

func TestResolveNilInformer(t *testing.T) {
	resolver := NewCgroupResolver(nil)
	resolver.RegisterContainer(100, "abc123")

	identity := resolver.Resolve(100)
	if identity != nil {
		t.Error("expected nil with nil informer")
	}
}

func TestMultipleRegistrations(t *testing.T) {
	informer := newMockInformer()
	informer.pods["new-container"] = &PodIdentity{
		PodName:   "new-pod",
		Namespace: "default",
	}

	resolver := NewCgroupResolver(informer)

	// Register, then re-register with a different container ID.
	resolver.RegisterContainer(100, "old-container")
	resolver.RegisterContainer(100, "new-container")

	identity := resolver.Resolve(100)
	if identity == nil {
		t.Fatal("expected non-nil")
	}
	if identity.PodName != "new-pod" {
		t.Errorf("expected new-pod, got %q", identity.PodName)
	}
}
