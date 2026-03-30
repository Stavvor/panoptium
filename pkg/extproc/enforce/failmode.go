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

package enforce

// FailureMode controls the behavior when the policy engine or ExtProc
// enforcement layer is unavailable or encounters an error during evaluation.
type FailureMode string

const (
	// FailOpen passes all traffic through without evaluation when the
	// policy engine is unavailable. A warning-level log and
	// enforcement.bypass event are emitted.
	FailOpen FailureMode = "open"

	// FailClosed returns 503 Service Unavailable for all traffic when
	// the policy engine is unavailable. An error-level log and
	// enforcement.unavailable event are emitted.
	FailClosed FailureMode = "closed"
)
