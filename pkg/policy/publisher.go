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
	"time"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
)

// PolicyDecisionEvent is emitted to the Event Bus for every policy evaluation.
// It contains the matched rule, action, triggering event, evaluation duration,
// and full predicate evaluation trace.
type PolicyDecisionEvent struct {
	eventbus.BaseEvent

	// Matched indicates whether any rule matched the event.
	Matched bool

	// MatchedRule is the name of the matched rule (empty if no match).
	MatchedRule string

	// MatchedRuleIndex is the index of the matched rule.
	MatchedRuleIndex int

	// ActionTaken is the action type that was applied.
	ActionTaken v1alpha1.ActionType

	// PolicyName is the name of the policy containing the matched rule.
	PolicyName string

	// PolicyNamespace is the namespace of the policy.
	PolicyNamespace string

	// TriggerCategory is the event category that was evaluated.
	TriggerCategory string

	// TriggerSubcategory is the event subcategory that was evaluated.
	TriggerSubcategory string

	// EvalDuration is how long the evaluation took.
	EvalDuration time.Duration

	// PredicateTrace records the evaluation result of each predicate.
	PredicateTrace []PredicateTraceEntry
}

// DecisionPublisher publishes policy decision events to the Event Bus.
// It uses non-blocking emission with drop-on-full semantics to avoid
// blocking the evaluation hot path.
type DecisionPublisher struct {
	bus eventbus.EventBus
}

// NewDecisionPublisher creates a new DecisionPublisher that emits to
// the given Event Bus.
func NewDecisionPublisher(bus eventbus.EventBus) *DecisionPublisher {
	return &DecisionPublisher{bus: bus}
}

// Publish emits a policy.decision event to the Event Bus. This is
// non-blocking: if a subscriber's buffer is full, the event is dropped
// for that subscriber.
func (p *DecisionPublisher) Publish(decision *Decision, triggerEvent *PolicyEvent) {
	pde := &PolicyDecisionEvent{
		BaseEvent: eventbus.BaseEvent{
			Type:  eventbus.EventTypePolicyDecision,
			Time:  time.Now(),
			ReqID: "", // Decision events don't have a request ID
			Proto: "policy",
		},
		Matched:            decision.Matched,
		MatchedRule:        decision.MatchedRule,
		MatchedRuleIndex:   decision.MatchedRuleIndex,
		ActionTaken:        decision.Action.Type,
		PolicyName:         decision.PolicyName,
		PolicyNamespace:    decision.PolicyNamespace,
		TriggerCategory:    triggerEvent.Category,
		TriggerSubcategory: triggerEvent.Subcategory,
		EvalDuration:       decision.EvaluationDuration,
		PredicateTrace:     decision.PredicateTrace,
	}

	p.bus.Emit(pde)
}
