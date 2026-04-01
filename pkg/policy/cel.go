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

package policy

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// celEnvOnce ensures the shared CEL environment is created exactly once.
var (
	celEnvOnce    sync.Once
	sharedCELEnv  *cel.Env
	celEnvInitErr error
)

// getCELEnv returns the shared CEL environment with Panoptium-specific
// variables and custom functions. The environment is created once and
// cached for the lifetime of the process.
func getCELEnv() (*cel.Env, error) {
	celEnvOnce.Do(func() {
		sharedCELEnv, celEnvInitErr = newCELEnv()
	})
	return sharedCELEnv, celEnvInitErr
}

// newCELEnv creates the Panoptium CEL environment with:
// - event.* string variables for all known event fields
// - event.* int variables for numeric fields
// - Custom function: string.glob(pattern string) -> bool
// - Custom function: string.inCIDR(cidr string) -> bool
// - Standard string.matches(regex) is provided by CEL stdlib
func newCELEnv() (*cel.Env, error) {
	// Declare event fields as top-level map variable.
	// We use a dynamic approach: declare 'event' as a map<string, dyn>
	// so any field can be accessed.
	return cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),

		// Custom function: string.glob(pattern) -> bool
		cel.Function("glob",
			cel.MemberOverload("string_glob_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(celGlobFunc),
			),
		),

		// Custom function: string.inCIDR(cidr) -> bool
		cel.Function("inCIDR",
			cel.MemberOverload("string_inCIDR_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(celInCIDRFunc),
			),
		),
	)
}

// celGlobFunc implements the glob(pattern) CEL function.
func celGlobFunc(lhs ref.Val, rhs ref.Val) ref.Val {
	str, ok := lhs.Value().(string)
	if !ok {
		return types.NewErr("glob: expected string receiver, got %T", lhs.Value())
	}
	pattern, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("glob: expected string pattern, got %T", rhs.Value())
	}
	matched, _ := matchGlob(pattern, str)
	return types.Bool(matched)
}

// celInCIDRFunc implements the inCIDR(cidr) CEL function.
func celInCIDRFunc(lhs ref.Val, rhs ref.Val) ref.Val {
	ipStr, ok := lhs.Value().(string)
	if !ok {
		return types.NewErr("inCIDR: expected string receiver, got %T", lhs.Value())
	}
	cidrStr, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("inCIDR: expected string CIDR, got %T", rhs.Value())
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return types.Bool(false)
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return types.NewErr("inCIDR: invalid CIDR %q: %v", cidrStr, err)
	}

	return types.Bool(ipNet.Contains(ip))
}

// compileCEL compiles a CEL expression string into a cel.Program.
// Returns a CompilationError if the expression is invalid.
func compileCEL(env *cel.Env, expr string, policyName, ruleName string, ruleIndex int) (cel.Program, error) {
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, &CompilationError{
			PolicyName: policyName,
			RuleName:   ruleName,
			RuleIndex:  ruleIndex,
			Field:      "predicates.cel",
			Message:    fmt.Sprintf("invalid CEL expression %q: %v", expr, issues.Err()),
			Cause:      issues.Err(),
		}
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, &CompilationError{
			PolicyName: policyName,
			RuleName:   ruleName,
			RuleIndex:  ruleIndex,
			Field:      "predicates.cel",
			Message:    fmt.Sprintf("failed to create CEL program for %q: %v", expr, err),
			Cause:      err,
		}
	}

	return prg, nil
}

// evaluateCELProgram evaluates a compiled CEL program against event fields.
// Returns (matched bool, error).
func evaluateCELProgram(prg cel.Program, event *PolicyEvent) (bool, error) {
	// Build the activation map: event -> map of field values
	eventMap := make(map[string]interface{})
	if event.Fields != nil {
		for k, v := range event.Fields {
			eventMap[k] = v
		}
	}

	out, _, err := prg.Eval(map[string]interface{}{
		"event": eventMap,
	})
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression returned %T, expected bool", out.Value())
	}

	return result, nil
}
