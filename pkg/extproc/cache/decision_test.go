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

package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/panoptium/panoptium/pkg/policy"
)

// --- Universal Tier Tests ---

func TestUniversalTier_StoreAndRetrieve(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "test-rule",
		Action: policy.CompiledAction{
			Type:       "deny",
			Parameters: map[string]string{"signature": "PAN-SIG-001"},
		},
		PolicyName:      "deny-curl",
		PolicyNamespace: "default",
	}

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
	c.Store(key, TierUniversal, decision, "default/deny-curl", "v1")

	got, hit := c.Lookup(key, TierUniversal)
	if !hit {
		t.Fatal("expected cache hit for universal tier, got miss")
	}
	if got.MatchedRule != "test-rule" {
		t.Errorf("expected MatchedRule 'test-rule', got %q", got.MatchedRule)
	}
	if got.PolicyName != "deny-curl" {
		t.Errorf("expected PolicyName 'deny-curl', got %q", got.PolicyName)
	}
	if got.Action.Parameters["signature"] != "PAN-SIG-001" {
		t.Errorf("expected signature PAN-SIG-001, got %q", got.Action.Parameters["signature"])
	}
}

func TestUniversalTier_CacheMissForUnknownKey(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "unknown-tool", Action: "execute"}
	_, hit := c.Lookup(key, TierUniversal)
	if hit {
		t.Fatal("expected cache miss for unknown key, got hit")
	}
}

func TestUniversalTier_TTLExpiration(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.UniversalTTL = 50 * time.Millisecond
	cfg.CleanupInterval = 10 * time.Millisecond
	c := NewPolicyDecisionCache(cfg)
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "ttl-rule",
		Action:      policy.CompiledAction{Type: "deny"},
	}

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
	c.Store(key, TierUniversal, decision, "default/deny-curl", "v1")

	// Should be a hit immediately
	_, hit := c.Lookup(key, TierUniversal)
	if !hit {
		t.Fatal("expected cache hit before TTL expiry")
	}

	// Wait for TTL expiry
	time.Sleep(100 * time.Millisecond)

	// Should be a miss after TTL
	_, hit = c.Lookup(key, TierUniversal)
	if hit {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestUniversalTier_OverwriteExistingEntry(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}

	d1 := &policy.Decision{Matched: true, MatchedRule: "rule-v1", Action: policy.CompiledAction{Type: "deny"}}
	c.Store(key, TierUniversal, d1, "default/deny-curl", "v1")

	d2 := &policy.Decision{Matched: true, MatchedRule: "rule-v2", Action: policy.CompiledAction{Type: "allow"}}
	c.Store(key, TierUniversal, d2, "default/deny-curl", "v2")

	got, hit := c.Lookup(key, TierUniversal)
	if !hit {
		t.Fatal("expected cache hit after overwrite")
	}
	if got.MatchedRule != "rule-v2" {
		t.Errorf("expected MatchedRule 'rule-v2' after overwrite, got %q", got.MatchedRule)
	}
}

// --- Task-Scoped Tier Tests ---

func TestTaskScopedTier_StoreAndRetrieve(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "session-rule",
		Action:      policy.CompiledAction{Type: "deny"},
	}

	key := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-abc-123"}
	c.Store(key, TierTaskScoped, decision, "default/deny-curl", "v1")

	got, hit := c.Lookup(key, TierTaskScoped)
	if !hit {
		t.Fatal("expected cache hit for task-scoped tier, got miss")
	}
	if got.MatchedRule != "session-rule" {
		t.Errorf("expected MatchedRule 'session-rule', got %q", got.MatchedRule)
	}
}

func TestTaskScopedTier_DifferentSessionsAreSeparate(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d1 := &policy.Decision{Matched: true, MatchedRule: "rule-session-1", Action: policy.CompiledAction{Type: "deny"}}
	d2 := &policy.Decision{Matched: true, MatchedRule: "rule-session-2", Action: policy.CompiledAction{Type: "allow"}}

	key1 := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-1"}
	key2 := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-2"}

	c.Store(key1, TierTaskScoped, d1, "default/deny-curl", "v1")
	c.Store(key2, TierTaskScoped, d2, "default/deny-curl", "v1")

	got1, hit1 := c.Lookup(key1, TierTaskScoped)
	got2, hit2 := c.Lookup(key2, TierTaskScoped)

	if !hit1 || !hit2 {
		t.Fatal("expected cache hits for both sessions")
	}
	if got1.MatchedRule != "rule-session-1" {
		t.Errorf("expected session-1 rule, got %q", got1.MatchedRule)
	}
	if got2.MatchedRule != "rule-session-2" {
		t.Errorf("expected session-2 rule, got %q", got2.MatchedRule)
	}
}

func TestTaskScopedTier_InvalidateOnSessionEnd(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d := &policy.Decision{Matched: true, MatchedRule: "session-rule", Action: policy.CompiledAction{Type: "deny"}}

	key := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-end-test"}
	c.Store(key, TierTaskScoped, d, "default/deny-curl", "v1")

	// Verify hit before invalidation
	_, hit := c.Lookup(key, TierTaskScoped)
	if !hit {
		t.Fatal("expected cache hit before session end")
	}

	// End the session
	c.InvalidateSession("session-end-test")

	// Should miss after session invalidation
	_, hit = c.Lookup(key, TierTaskScoped)
	if hit {
		t.Fatal("expected cache miss after session end")
	}
}

func TestTaskScopedTier_InvalidateSessionOnlyAffectsTargetSession(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d1 := &policy.Decision{Matched: true, MatchedRule: "keep-rule", Action: policy.CompiledAction{Type: "deny"}}
	d2 := &policy.Decision{Matched: true, MatchedRule: "evict-rule", Action: policy.CompiledAction{Type: "deny"}}

	key1 := CacheKey{Tool: "curl", Action: "execute", SessionID: "keep-session"}
	key2 := CacheKey{Tool: "curl", Action: "execute", SessionID: "evict-session"}

	c.Store(key1, TierTaskScoped, d1, "default/deny-curl", "v1")
	c.Store(key2, TierTaskScoped, d2, "default/deny-curl", "v1")

	// Invalidate only evict-session
	c.InvalidateSession("evict-session")

	// keep-session should still be a hit
	_, hit := c.Lookup(key1, TierTaskScoped)
	if !hit {
		t.Fatal("expected cache hit for keep-session after invalidating evict-session")
	}

	// evict-session should be a miss
	_, hit = c.Lookup(key2, TierTaskScoped)
	if hit {
		t.Fatal("expected cache miss for evict-session after invalidation")
	}
}

// --- Once Tier Tests ---

func TestOnceTier_AlwaysReturnsCacheMiss(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	decision := &policy.Decision{
		Matched:     true,
		MatchedRule: "once-rule",
		Action:      policy.CompiledAction{Type: "deny"},
	}

	key := CacheKey{Tool: "curl", Action: "execute"}

	// Store should succeed without error but lookup always misses
	c.Store(key, TierOnce, decision, "default/deny-curl", "v1")

	_, hit := c.Lookup(key, TierOnce)
	if hit {
		t.Fatal("expected cache miss for once tier, got hit")
	}
}

func TestOnceTier_MultipleStoresStillMiss(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute"}

	for i := 0; i < 5; i++ {
		d := &policy.Decision{Matched: true, MatchedRule: "once-rule", Action: policy.CompiledAction{Type: "deny"}}
		c.Store(key, TierOnce, d, "default/deny-curl", "v1")

		_, hit := c.Lookup(key, TierOnce)
		if hit {
			t.Fatalf("expected cache miss for once tier on iteration %d", i)
		}
	}
}

// --- Cache Tier Selection Tests ---

func TestCacheTierSelection_UniversalForGlobalRules(t *testing.T) {
	tier := SelectTier("universal")
	if tier != TierUniversal {
		t.Errorf("expected TierUniversal for 'universal' annotation, got %v", tier)
	}
}

func TestCacheTierSelection_TaskScopedForSessionRules(t *testing.T) {
	tier := SelectTier("task-scoped")
	if tier != TierTaskScoped {
		t.Errorf("expected TierTaskScoped for 'task-scoped' annotation, got %v", tier)
	}
}

func TestCacheTierSelection_OnceForPerInvocationRules(t *testing.T) {
	tier := SelectTier("once")
	if tier != TierOnce {
		t.Errorf("expected TierOnce for 'once' annotation, got %v", tier)
	}
}

func TestCacheTierSelection_DefaultIsUniversal(t *testing.T) {
	tier := SelectTier("")
	if tier != TierUniversal {
		t.Errorf("expected TierUniversal for empty annotation, got %v", tier)
	}
}

func TestCacheTierSelection_UnknownDefaultsToUniversal(t *testing.T) {
	tier := SelectTier("unknown-tier")
	if tier != TierUniversal {
		t.Errorf("expected TierUniversal for unknown annotation, got %v", tier)
	}
}

// --- Concurrent Access Tests ---

func TestConcurrentCacheAccess_UniversalTier(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
			d := &policy.Decision{Matched: true, MatchedRule: "concurrent-rule", Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierUniversal, d, "default/deny-curl", "v1")
		}(i)
	}

	// Concurrent reads
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/deny-curl"}
			c.Lookup(key, TierUniversal)
		}(i)
	}

	wg.Wait()
}

func TestConcurrentCacheAccess_MixedTiers(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	var wg sync.WaitGroup
	iterations := 50

	for i := 0; i < iterations; i++ {
		wg.Add(3)

		// Universal tier operations
		go func(n int) {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
			d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierUniversal, d, "default/pol", "v1")
			c.Lookup(key, TierUniversal)
		}(i)

		// Task-scoped tier operations
		go func(n int) {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", SessionID: "session-concurrent"}
			d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierTaskScoped, d, "default/pol", "v1")
			c.Lookup(key, TierTaskScoped)
		}(i)

		// Invalidation operations
		go func(n int) {
			defer wg.Done()
			c.InvalidatePolicy("default/pol")
			c.InvalidateSession("session-concurrent")
		}(i)
	}

	wg.Wait()
}

func TestConcurrentCacheAccess_StoreAndInvalidate(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	var wg sync.WaitGroup

	// Concurrent stores and invalidations should not panic
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
			d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}
			c.Store(key, TierUniversal, d, "default/pol", "v1")
		}()
		go func() {
			defer wg.Done()
			c.InvalidatePolicy("default/pol")
		}()
	}

	wg.Wait()
}

// --- Stats/Metrics Tests ---

func TestCacheStats_TracksHitsAndMisses(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	key := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}

	// Miss
	c.Lookup(key, TierUniversal)

	// Store, then hit
	c.Store(key, TierUniversal, d, "default/pol", "v1")
	c.Lookup(key, TierUniversal)
	c.Lookup(key, TierUniversal)

	stats := c.Stats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}

// --- Flush Tests ---

func TestFlush_ClearsAllTiers(t *testing.T) {
	c := NewPolicyDecisionCache(DefaultCacheConfig())
	defer c.Stop()

	d := &policy.Decision{Matched: true, Action: policy.CompiledAction{Type: "deny"}}

	uniKey := CacheKey{Tool: "curl", Action: "execute", PolicyKey: "default/pol"}
	taskKey := CacheKey{Tool: "curl", Action: "execute", SessionID: "sess-1"}

	c.Store(uniKey, TierUniversal, d, "default/pol", "v1")
	c.Store(taskKey, TierTaskScoped, d, "default/pol", "v1")

	c.Flush()

	_, hit1 := c.Lookup(uniKey, TierUniversal)
	_, hit2 := c.Lookup(taskKey, TierTaskScoped)

	if hit1 || hit2 {
		t.Fatal("expected all tiers to be empty after flush")
	}
}
