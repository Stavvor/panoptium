# Network Policy Examples

Panoptium uses a **layered security** model:

- **Kubernetes NetworkPolicy** handles network admission (which pods can reach the gateway).
- **ExtProc + AgentPolicy** handles semantic/protocol enforcement (tool authorization, rate limiting, threat signatures, content inspection).

This separation ensures network admission is enforced at the kernel/CNI level and cannot be bypassed by application-level failures or fail-open modes.

## Default Behavior

The Helm chart ships a default NetworkPolicy (`networkPolicy.enabled: true`) that allows ingress from all in-cluster pods to the gateway ExtProc port. This provides a baseline that you can tighten.

## Override Examples

| File | What it does |
|------|-------------|
| `allow-all-namespaces.yaml` | Default: all pods in the cluster can reach the gateway |
| `restrict-to-namespace.yaml` | Only pods in a specific namespace can reach the gateway |
| `restrict-to-labeled-pods.yaml` | Only pods with a specific label can reach the gateway |

## Usage

```bash
# Use default (allow all namespaces)
helm install panoptium chart/panoptium

# Restrict to a single namespace
helm install panoptium chart/panoptium -f examples/network-policies/restrict-to-namespace.yaml

# Disable the default NetworkPolicy entirely
helm install panoptium chart/panoptium --set networkPolicy.enabled=false
```

## Relationship to AgentPolicy

NetworkPolicy controls **who can connect**. AgentPolicy controls **what they can do once connected**. Both are needed for defense in depth:

1. NetworkPolicy blocks unauthorized pods at the network level (kernel/CNI).
2. AgentPolicy inspects authorized traffic for policy violations (application level).
