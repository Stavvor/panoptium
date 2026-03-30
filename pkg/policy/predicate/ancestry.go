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
	"path/filepath"

	"github.com/panoptium/panoptium/pkg/policy"
)

// AncestorMatchMode defines how ancestor process names are matched.
type AncestorMatchMode int

const (
	// AncestorMatchExact performs exact string matching on ancestor name.
	AncestorMatchExact AncestorMatchMode = iota

	// AncestorMatchGlob performs glob pattern matching on ancestor name.
	AncestorMatchGlob
)

// ProcessInfo holds information about a process in the process tree.
type ProcessInfo struct {
	// PID is the process identifier.
	PID int

	// Name is the process executable name.
	Name string
}

// ProcessTreeProvider is an interface for retrieving the ancestry chain
// of a process by its PID. Implementations may read from /proc, eBPF maps,
// or Tetragon event chains.
type ProcessTreeProvider interface {
	// GetAncestry returns the ancestry chain for the given PID, ordered from
	// the process itself (index 0) up through its ancestors. Returns nil if
	// the process tree is unavailable for the given PID.
	GetAncestry(pid int) []ProcessInfo
}

// ProcessAncestryEvaluator evaluates process ancestry predicates by checking
// whether any ancestor of the event's process matches the configured pattern.
// It implements the PredicateEvaluator interface.
type ProcessAncestryEvaluator struct {
	// PIDField is the event field containing the process PID.
	PIDField string

	// AncestorName is the process name (or pattern) to search for in the ancestry.
	AncestorName string

	// MatchMode determines whether to match exactly or via glob pattern.
	MatchMode AncestorMatchMode

	// ProcessTree is the provider for process ancestry information.
	ProcessTree ProcessTreeProvider
}

// Evaluate checks whether any ancestor of the event's process matches the
// configured ancestor name pattern. Returns false if the PID field is missing,
// not numeric, or the process tree is unavailable.
func (e *ProcessAncestryEvaluator) Evaluate(event *policy.PolicyEvent) (bool, error) {
	fieldValue := extractField(e.PIDField, event)
	if fieldValue == nil {
		return false, nil
	}

	pid, ok := coerceToPID(fieldValue)
	if !ok {
		return false, nil
	}

	ancestry := e.ProcessTree.GetAncestry(pid)
	if len(ancestry) == 0 {
		return false, nil
	}

	// Skip the process itself (index 0), check ancestors only
	for i := 1; i < len(ancestry); i++ {
		if e.matchesAncestor(ancestry[i].Name) {
			return true, nil
		}
	}

	return false, nil
}

// matchesAncestor checks if the given process name matches the configured pattern.
func (e *ProcessAncestryEvaluator) matchesAncestor(name string) bool {
	switch e.MatchMode {
	case AncestorMatchExact:
		return name == e.AncestorName
	case AncestorMatchGlob:
		matched, _ := filepath.Match(e.AncestorName, name)
		return matched
	default:
		return name == e.AncestorName
	}
}

// coerceToPID converts a field value to a process ID (int).
// Supports int, int64, and float64 values.
func coerceToPID(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case int32:
		return int(n), true
	default:
		return 0, false
	}
}
