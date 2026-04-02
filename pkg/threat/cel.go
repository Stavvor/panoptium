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

package threat

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// CELEvaluator compiles and evaluates CEL expressions for threat detection.
// It provides custom functions: shannon_entropy, regex_match.
type CELEvaluator struct {
	mu       sync.RWMutex
	env      *cel.Env
	programs map[string]cel.Program
}

// NewCELEvaluator creates a new CEL evaluator with the threat detection environment.
func NewCELEvaluator() *CELEvaluator {
	env, err := newThreatCELEnv()
	if err != nil {
		// This should never happen since the environment definition is static
		panic(fmt.Sprintf("failed to create threat CEL environment: %v", err))
	}
	return &CELEvaluator{
		env:      env,
		programs: make(map[string]cel.Program),
	}
}

// newThreatCELEnv creates a CEL environment with threat-specific variables and functions.
func newThreatCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// content: the text being evaluated
		cel.Variable("content", cel.StringType),

		// Custom function: shannon_entropy(string) -> double
		cel.Function("shannon_entropy",
			cel.Overload("shannon_entropy_string",
				[]*cel.Type{cel.StringType},
				cel.DoubleType,
				cel.UnaryBinding(celShannonEntropyFunc),
			),
		),

		// Custom function: regex_match(string, string) -> bool
		cel.Function("regex_match",
			cel.Overload("regex_match_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(celRegexMatchFunc),
			),
		),
	)
}

// celShannonEntropyFunc implements the shannon_entropy(string) CEL function.
func celShannonEntropyFunc(val ref.Val) ref.Val {
	s, ok := val.Value().(string)
	if !ok {
		return types.NewErr("shannon_entropy: expected string, got %T", val.Value())
	}
	return types.Double(ShannonEntropy(s))
}

// celRegexMatchFunc implements the regex_match(content, pattern) CEL function.
func celRegexMatchFunc(lhs ref.Val, rhs ref.Val) ref.Val {
	content, ok := lhs.Value().(string)
	if !ok {
		return types.NewErr("regex_match: expected string content, got %T", lhs.Value())
	}
	pattern, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("regex_match: expected string pattern, got %T", rhs.Value())
	}

	matched, err := regexp.MatchString(pattern, content)
	if err != nil {
		return types.NewErr("regex_match: invalid pattern %q: %v", pattern, err)
	}
	return types.Bool(matched)
}

// Compile compiles a CEL expression and caches the program.
// Returns an error if the expression is invalid or does not return a boolean.
func (e *CELEvaluator) Compile(name, expression string) error {
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("CEL compilation error for %q: %w", name, issues.Err())
	}

	// Verify the expression returns a boolean
	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("CEL expression %q must return bool, got %s", name, ast.OutputType())
	}

	prg, err := e.env.Program(ast)
	if err != nil {
		return fmt.Errorf("CEL program creation error for %q: %w", name, err)
	}

	e.mu.Lock()
	e.programs[name] = prg
	e.mu.Unlock()

	return nil
}

// Evaluate evaluates a previously compiled CEL expression against the given content.
// Returns true if the expression matches, false otherwise.
func (e *CELEvaluator) Evaluate(name, content string) (bool, error) {
	e.mu.RLock()
	prg, ok := e.programs[name]
	e.mu.RUnlock()

	if !ok {
		return false, fmt.Errorf("CEL program %q not found", name)
	}

	out, _, err := prg.Eval(map[string]interface{}{
		"content": content,
	})
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error for %q: %w", name, err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression %q returned %T, expected bool", name, out.Value())
	}

	return result, nil
}
