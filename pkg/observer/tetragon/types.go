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

// Package tetragon provides a Tetragon gRPC event consumer and translator
// for the Panoptium kernel observation layer.
package tetragon

// EventType identifies the kind of Tetragon event.
type EventType string

const (
	// EventTypeProcessExec represents a process execution event.
	EventTypeProcessExec EventType = "process_exec"

	// EventTypeProcessExit represents a process exit event.
	EventTypeProcessExit EventType = "process_exit"

	// EventTypeProcessKprobe represents a kprobe event.
	EventTypeProcessKprobe EventType = "process_kprobe"

	// EventTypeProcessTracepoint represents a tracepoint event.
	EventTypeProcessTracepoint EventType = "process_tracepoint"

	// EventTypeProcessLSM represents a BPF-LSM event.
	EventTypeProcessLSM EventType = "process_lsm"
)

// RawEvent is the Panoptium-side representation of a Tetragon event.
// It abstracts away the Tetragon protobuf types, providing a clean
// internal event structure that the translator converts to eventbus.Event.
type RawEvent struct {
	// Type identifies the kind of Tetragon event.
	Type EventType

	// ProcessPID is the PID of the process that triggered the event.
	ProcessPID uint32

	// ProcessComm is the executable name (comm) of the process.
	ProcessComm string

	// ParentPID is the PID of the parent process.
	ParentPID uint32

	// ParentComm is the executable name of the parent process.
	ParentComm string

	// Namespace is the Kubernetes namespace (from Tetragon metadata).
	Namespace string

	// PodName is the Kubernetes pod name (from Tetragon metadata).
	PodName string

	// ContainerID is the container runtime ID.
	ContainerID string

	// Labels contains the Kubernetes labels of the pod.
	Labels map[string]string

	// KprobeFunc is the kernel function name for kprobe events.
	KprobeFunc string

	// KprobeArgs contains the captured kprobe arguments.
	KprobeArgs map[string]interface{}

	// LSMHook is the LSM hook name for LSM events.
	LSMHook string

	// LSMAction is the enforcement action (e.g., "Override", "Signal").
	LSMAction string

	// Timestamp is the kernel timestamp of the event.
	Timestamp uint64

	// CgroupID is the cgroup ID of the process.
	CgroupID uint64
}

// ConnectionState represents the state of the Tetragon gRPC connection.
type ConnectionState string

const (
	// StateDisconnected indicates the client is not connected.
	StateDisconnected ConnectionState = "disconnected"

	// StateConnecting indicates the client is attempting to connect.
	StateConnecting ConnectionState = "connecting"

	// StateConnected indicates the client is connected and receiving events.
	StateConnected ConnectionState = "connected"

	// StateReconnecting indicates the client is reconnecting after a failure.
	StateReconnecting ConnectionState = "reconnecting"
)
