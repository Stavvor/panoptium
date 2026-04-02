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

package predicate

import (
	"sync"
	"time"

	"github.com/panoptium/panoptium/pkg/policy"
)

// SlidingWindowCounter tracks event counts within a sliding time window,
// partitioned by a groupBy key. It is safe for concurrent use from
// multiple goroutines.
type SlidingWindowCounter struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[string][]time.Time
}

// NewSlidingWindowCounter creates a new SlidingWindowCounter with the
// specified sliding window duration.
func NewSlidingWindowCounter(window time.Duration) *SlidingWindowCounter {
	return &SlidingWindowCounter{
		window:  window,
		entries: make(map[string][]time.Time),
	}
}

// Increment records a new event for the given groupBy key.
func (c *SlidingWindowCounter) Increment(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = append(c.entries[key], time.Now())
}

// Count returns the number of events within the sliding window for the
// given groupBy key. Expired entries are pruned during counting.
func (c *SlidingWindowCounter) Count(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.countLocked(key)
}

// countLocked returns the count for a key while the lock is already held.
// It prunes expired entries.
func (c *SlidingWindowCounter) countLocked(key string) int {
	timestamps, ok := c.entries[key]
	if !ok {
		return 0
	}

	cutoff := time.Now().Add(-c.window)
	valid := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	c.entries[key] = valid
	return len(valid)
}

// IncrementAndCheck atomically increments the counter for the given key
// and returns true if the new count exceeds the specified limit. This
// provides a race-free increment-then-check operation for per-rule dynamic
// limits.
func (c *SlidingWindowCounter) IncrementAndCheck(key string, limit int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = append(c.entries[key], time.Now())
	return c.countLocked(key) > limit
}

// Cleanup removes all expired entries across all keys. This can be called
// periodically by a background goroutine to prevent unbounded memory growth.
func (c *SlidingWindowCounter) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.window)
	for key, timestamps := range c.entries {
		valid := timestamps[:0]
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}
		if len(valid) == 0 {
			delete(c.entries, key)
		} else {
			c.entries[key] = valid
		}
	}
}

// RateLimitEvaluator evaluates rate limiting predicates by checking whether
// the event count for a groupBy key exceeds the configured limit within
// the sliding window. Implements the PredicateEvaluator interface.
type RateLimitEvaluator struct {
	// Counter is the sliding window counter for tracking event counts.
	Counter *SlidingWindowCounter

	// Limit is the maximum number of events allowed within the window.
	// When count >= Limit, the predicate matches (rate limit exceeded).
	Limit int

	// GroupByField is the event field used to partition counters
	// (e.g., "agentID", "toolName").
	GroupByField string

	// AutoIncrement, when true, causes each Evaluate call to automatically
	// increment the counter before checking the limit. This is useful when
	// the evaluator is the sole source of event counting.
	AutoIncrement bool
}

// Evaluate checks whether the rate limit has been exceeded for the event's
// groupBy key. Returns true if the count within the window is >= Limit,
// indicating a rate limit violation. Returns false if the groupBy field is
// missing from the event.
func (e *RateLimitEvaluator) Evaluate(event *policy.PolicyEvent) (bool, error) {
	fieldValue := extractField(e.GroupByField, event)
	if fieldValue == nil {
		return false, nil
	}

	key := coerceToString(fieldValue)

	if e.AutoIncrement {
		e.Counter.Increment(key)
	}

	count := e.Counter.Count(key)
	return count >= e.Limit, nil
}
