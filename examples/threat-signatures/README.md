# Threat Signatures

`ThreatSignature` is a cluster-scoped CRD that defines detection patterns for known AI agent attacks. Panoptium ships with [9 default signatures](../../chart/panoptium/templates/threat-signatures/) covering prompt injection, tool poisoning, data exfiltration, and obfuscation. You can add your own.

## How detection works

When a request passes through the ExtProc filter, Panoptium extracts content from specific targets — `tool_description`, `tool_args`, or `message_content` — and runs every matching signature against it.

Each signature defines one or more detection methods:

- **Regex patterns** with a weight (0.0–1.0) indicating confidence
- **Shannon entropy** thresholds to catch encoded/obfuscated payloads
- **Base64 detection** for encoded instructions above a minimum length
- **CEL expressions** for structured matching logic

If any pattern matches, a `MatchResult` is produced with a composite score (max weight + small boost for multiple hits, capped at 1.0). The result carries the signature name, category, severity, and MITRE ATLAS reference.

Signatures alone don't block anything. They produce match results. An `AgentPolicy` with a `threatSignatures` selector decides what to do with those results — deny, alert, escalate.

## Current limitations

The current detection engine is **pattern-based**. It works well for known attack patterns with distinctive syntax, but has inherent limitations:

**False positives are expected.** A legitimate database migration tool with a description like *"Replaces the original schema with the new version"* will match the `tool-shadowing` signature because the regex sees "replaces the original" — the same phrase an attacker would use to hijack a tool.

**No semantic understanding.** The engine doesn't know whether "ignore previous instructions" appears in a malicious tool description trying to hijack an LLM, or in a legitimate tool that manages instruction templates. It just matches the regex.

**Static analysis only.** Signatures evaluate content at a single point in time. They can't detect behavioral patterns like "this tool's description changed since yesterday" or "this tool name shadows another tool registered 5 minutes ago."

## Mitigations for false positives

1. **Weights are not thresholds.** A match with weight 0.4 is not treated the same as 0.9. Policy rules can use severity selectors to only act on HIGH/CRITICAL matches, letting LOW matches pass through as audit events.

2. **Allow overrides.** Write an `AgentPolicy` with higher priority that explicitly allows known-good tools:

   ```yaml
   kind: AgentPolicy
   spec:
     priority: 200  # higher than the deny policy
     rules:
       - name: trust-db-migrate
         predicates:
           - cel: "event.toolName == 'db_migrate'"
         action:
           type: allow
   ```

3. **Audit mode.** Deploy signatures with `enforcementMode: audit` first. Review what matches before switching to `enforcing`.

## Planned improvements

The regex-based engine is the first layer. Future detection capabilities (tracked in the project roadmap) include:

- **MCP tool poisoning detector** — compares tool descriptions against previously seen versions, uses entropy analysis and name-vs-description semantic coherence checks. Code is written (`pkg/observer/protocol/mcp/poisoning.go`), not yet wired into the operator.

- **Intent-action correlation** — instead of just inspecting tool descriptions, correlates what the agent *declared* (via tool_use blocks) with what it *actually did* (kernel syscalls observed via eBPF). Detects divergence even when signatures don't match.

- **Behavioral anomaly detection** — three-tier system: in-kernel eBPF rules for known-bad syscall patterns, userspace statistical analysis (EWMA, Jensen-Shannon divergence), and async ML models (graph autoencoders, Isolation Forest) for fleet-wide anomaly correlation.

- **Cross-layer detection correlation** — combines signals from kernel, network, application protocol, and LLM streaming layers to detect multi-stage attacks that no single layer would catch alone.

## Writing custom signatures

This directory contains standalone examples. The Helm chart ships its own set in `chart/panoptium/templates/threat-signatures/` — those are deployed automatically.

To add a custom signature, apply it directly:

```bash
kubectl apply -f examples/threat-signatures/mcp-credential-harvesting.yaml
```

See the examples below for the full CRD structure with regex, entropy, and multi-target patterns.
