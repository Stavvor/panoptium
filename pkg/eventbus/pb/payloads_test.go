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

package pb

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestSyscallEventPayload verifies SyscallEvent fields round-trip correctly
// when embedded as a PanoptiumEvent payload.
func TestSyscallEventPayload(t *testing.T) {
	evt := &PanoptiumEvent{
		Id:       "01HZTEST_SYSCALL",
		Category: "syscall",
		Payload: &PanoptiumEvent_SyscallEvent{
			SyscallEvent: &SyscallEvent{
				Pid:        1234,
				Comm:       "python3",
				SyscallNr:  59, // execve
				Args:       []string{"/usr/bin/python3", "script.py"},
				ReturnCode: 0,
				CgroupId:   42,
			},
		},
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	sc := restored.GetSyscallEvent()
	if sc == nil {
		t.Fatal("SyscallEvent payload is nil")
	}
	if sc.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", sc.Pid)
	}
	if sc.Comm != "python3" {
		t.Errorf("Comm = %q, want %q", sc.Comm, "python3")
	}
	if sc.SyscallNr != 59 {
		t.Errorf("SyscallNr = %d, want 59", sc.SyscallNr)
	}
	if len(sc.Args) != 2 {
		t.Fatalf("Args length = %d, want 2", len(sc.Args))
	}
	if sc.Args[0] != "/usr/bin/python3" {
		t.Errorf("Args[0] = %q, want %q", sc.Args[0], "/usr/bin/python3")
	}
	if sc.ReturnCode != 0 {
		t.Errorf("ReturnCode = %d, want 0", sc.ReturnCode)
	}
	if sc.CgroupId != 42 {
		t.Errorf("CgroupId = %d, want 42", sc.CgroupId)
	}
}

// TestNetworkEventPayload verifies NetworkEvent fields round-trip correctly.
func TestNetworkEventPayload(t *testing.T) {
	evt := &PanoptiumEvent{
		Id:       "01HZTEST_NETWORK",
		Category: "network",
		Payload: &PanoptiumEvent_NetworkEvent{
			NetworkEvent: &NetworkEvent{
				SrcIp:    "10.0.0.5",
				SrcPort:  43210,
				DstIp:    "192.168.1.100",
				DstPort:  443,
				Protocol: "tcp",
				BytesTx:  1024,
				BytesRx:  2048,
			},
		},
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	net := restored.GetNetworkEvent()
	if net == nil {
		t.Fatal("NetworkEvent payload is nil")
	}
	if net.SrcIp != "10.0.0.5" {
		t.Errorf("SrcIp = %q, want %q", net.SrcIp, "10.0.0.5")
	}
	if net.SrcPort != 43210 {
		t.Errorf("SrcPort = %d, want 43210", net.SrcPort)
	}
	if net.DstIp != "192.168.1.100" {
		t.Errorf("DstIp = %q, want %q", net.DstIp, "192.168.1.100")
	}
	if net.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", net.DstPort)
	}
	if net.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want %q", net.Protocol, "tcp")
	}
	if net.BytesTx != 1024 {
		t.Errorf("BytesTx = %d, want 1024", net.BytesTx)
	}
	if net.BytesRx != 2048 {
		t.Errorf("BytesRx = %d, want 2048", net.BytesRx)
	}
}

// TestProtocolEventPayload verifies ProtocolEvent fields round-trip correctly.
func TestProtocolEventPayload(t *testing.T) {
	evt := &PanoptiumEvent{
		Id:       "01HZTEST_PROTOCOL",
		Category: "protocol",
		Payload: &PanoptiumEvent_ProtocolEvent{
			ProtocolEvent: &ProtocolEvent{
				HttpMethod:  "POST",
				Url:         "https://api.openai.com/v1/chat/completions",
				Headers:     map[string]string{"Content-Type": "application/json", "Authorization": "Bearer ***"},
				StatusCode:  200,
				ContentType: "text/event-stream",
			},
		},
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	p := restored.GetProtocolEvent()
	if p == nil {
		t.Fatal("ProtocolEvent payload is nil")
	}
	if p.HttpMethod != "POST" {
		t.Errorf("HttpMethod = %q, want %q", p.HttpMethod, "POST")
	}
	if p.Url != "https://api.openai.com/v1/chat/completions" {
		t.Errorf("Url = %q, want %q", p.Url, "https://api.openai.com/v1/chat/completions")
	}
	if p.Headers["Content-Type"] != "application/json" {
		t.Errorf("Headers[Content-Type] = %q, want %q", p.Headers["Content-Type"], "application/json")
	}
	if p.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", p.StatusCode)
	}
	if p.ContentType != "text/event-stream" {
		t.Errorf("ContentType = %q, want %q", p.ContentType, "text/event-stream")
	}
}

// TestLLMStreamEventPayload verifies LLMStreamEvent fields round-trip correctly.
func TestLLMStreamEventPayload(t *testing.T) {
	evt := &PanoptiumEvent{
		Id:       "01HZTEST_LLM",
		Category: "llm",
		Payload: &PanoptiumEvent_LlmStreamEvent{
			LlmStreamEvent: &LLMStreamEvent{
				Model:        "gpt-4",
				Provider:     "openai",
				Messages:     []string{"Hello, world!", "How can I help you?"},
				Tokens:       150,
				TtftMs:       85.5,
				FinishReason: "stop",
				ToolCalls: []*ToolCall{
					{
						Id:        "call_abc123",
						Name:      "search",
						Arguments: `{"query": "latest news"}`,
					},
				},
			},
		},
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	llm := restored.GetLlmStreamEvent()
	if llm == nil {
		t.Fatal("LLMStreamEvent payload is nil")
	}
	if llm.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", llm.Model, "gpt-4")
	}
	if llm.Provider != "openai" {
		t.Errorf("Provider = %q, want %q", llm.Provider, "openai")
	}
	if len(llm.Messages) != 2 {
		t.Fatalf("Messages length = %d, want 2", len(llm.Messages))
	}
	if llm.Tokens != 150 {
		t.Errorf("Tokens = %d, want 150", llm.Tokens)
	}
	if llm.TtftMs != 85.5 {
		t.Errorf("TtftMs = %f, want 85.5", llm.TtftMs)
	}
	if llm.FinishReason != "stop" {
		t.Errorf("FinishReason = %q, want %q", llm.FinishReason, "stop")
	}
	if len(llm.ToolCalls) != 1 {
		t.Fatalf("ToolCalls length = %d, want 1", len(llm.ToolCalls))
	}
	tc := llm.ToolCalls[0]
	if tc.Id != "call_abc123" {
		t.Errorf("ToolCall.Id = %q, want %q", tc.Id, "call_abc123")
	}
	if tc.Name != "search" {
		t.Errorf("ToolCall.Name = %q, want %q", tc.Name, "search")
	}
	if tc.Arguments != `{"query": "latest news"}` {
		t.Errorf("ToolCall.Arguments = %q, want %q", tc.Arguments, `{"query": "latest news"}`)
	}
}

// TestPolicyEventPayload verifies PolicyEvent fields round-trip correctly.
func TestPolicyEventPayload(t *testing.T) {
	evt := &PanoptiumEvent{
		Id:       "01HZTEST_POLICY",
		Category: "policy",
		Severity: Severity_HIGH,
		Payload: &PanoptiumEvent_PolicyEvent{
			PolicyEvent: &PolicyEvent{
				PolicyName:      "deny-external-access",
				RuleIndex:       3,
				Action:          "block",
				MatchDetails:    "matched destination 1.2.3.4:443",
				EnforcementMode: "enforce",
			},
		},
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	pol := restored.GetPolicyEvent()
	if pol == nil {
		t.Fatal("PolicyEvent payload is nil")
	}
	if pol.PolicyName != "deny-external-access" {
		t.Errorf("PolicyName = %q, want %q", pol.PolicyName, "deny-external-access")
	}
	if pol.RuleIndex != 3 {
		t.Errorf("RuleIndex = %d, want 3", pol.RuleIndex)
	}
	if pol.Action != "block" {
		t.Errorf("Action = %q, want %q", pol.Action, "block")
	}
	if pol.MatchDetails != "matched destination 1.2.3.4:443" {
		t.Errorf("MatchDetails = %q, want %q", pol.MatchDetails, "matched destination 1.2.3.4:443")
	}
	if pol.EnforcementMode != "enforce" {
		t.Errorf("EnforcementMode = %q, want %q", pol.EnforcementMode, "enforce")
	}
}

// TestLifecycleEventPayload verifies LifecycleEvent fields round-trip correctly.
func TestLifecycleEventPayload(t *testing.T) {
	evt := &PanoptiumEvent{
		Id:       "01HZTEST_LIFECYCLE",
		Category: "lifecycle",
		Payload: &PanoptiumEvent_LifecycleEvent{
			LifecycleEvent: &LifecycleEvent{
				PodName:   "agent-chatbot-abc",
				Namespace: "production",
				Phase:     "Running",
				ContainerStatuses: []*ContainerStatus{
					{
						Name:         "agent",
						State:        "running",
						Ready:        true,
						RestartCount: 0,
					},
					{
						Name:         "sidecar",
						State:        "running",
						Ready:        true,
						RestartCount: 2,
					},
				},
				RestartCount: 2,
			},
		},
	}

	data, err := proto.Marshal(evt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	restored := &PanoptiumEvent{}
	if err := proto.Unmarshal(data, restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	lc := restored.GetLifecycleEvent()
	if lc == nil {
		t.Fatal("LifecycleEvent payload is nil")
	}
	if lc.PodName != "agent-chatbot-abc" {
		t.Errorf("PodName = %q, want %q", lc.PodName, "agent-chatbot-abc")
	}
	if lc.Namespace != "production" {
		t.Errorf("Namespace = %q, want %q", lc.Namespace, "production")
	}
	if lc.Phase != "Running" {
		t.Errorf("Phase = %q, want %q", lc.Phase, "Running")
	}
	if len(lc.ContainerStatuses) != 2 {
		t.Fatalf("ContainerStatuses length = %d, want 2", len(lc.ContainerStatuses))
	}
	cs := lc.ContainerStatuses[0]
	if cs.Name != "agent" {
		t.Errorf("ContainerStatuses[0].Name = %q, want %q", cs.Name, "agent")
	}
	if !cs.Ready {
		t.Error("ContainerStatuses[0].Ready should be true")
	}
	if cs.RestartCount != 0 {
		t.Errorf("ContainerStatuses[0].RestartCount = %d, want 0", cs.RestartCount)
	}
	cs2 := lc.ContainerStatuses[1]
	if cs2.RestartCount != 2 {
		t.Errorf("ContainerStatuses[1].RestartCount = %d, want 2", cs2.RestartCount)
	}
	if lc.RestartCount != 2 {
		t.Errorf("RestartCount = %d, want 2", lc.RestartCount)
	}
}

// TestPayloadOneofExclusivity verifies that only one payload type can be set at a time.
func TestPayloadOneofExclusivity(t *testing.T) {
	// Set syscall payload
	evt := &PanoptiumEvent{
		Id: "01HZTEST_ONEOF",
		Payload: &PanoptiumEvent_SyscallEvent{
			SyscallEvent: &SyscallEvent{Pid: 1},
		},
	}

	// Verify other payloads are nil
	if evt.GetNetworkEvent() != nil {
		t.Error("NetworkEvent should be nil when SyscallEvent is set")
	}
	if evt.GetProtocolEvent() != nil {
		t.Error("ProtocolEvent should be nil when SyscallEvent is set")
	}
	if evt.GetLlmStreamEvent() != nil {
		t.Error("LlmStreamEvent should be nil when SyscallEvent is set")
	}
	if evt.GetPolicyEvent() != nil {
		t.Error("PolicyEvent should be nil when SyscallEvent is set")
	}
	if evt.GetLifecycleEvent() != nil {
		t.Error("LifecycleEvent should be nil when SyscallEvent is set")
	}
	if evt.GetSyscallEvent() == nil {
		t.Error("SyscallEvent should not be nil")
	}
}
