# AI Agent Security Standards & Threat Frameworks Analysis

**Date:** 2026-03-29
**Scope:** Official security frameworks, threat taxonomies, and standards documents for AI agent security monitoring

---

## Table of Contents

1. [OWASP](#1-owasp)
2. [MITRE](#2-mitre)
3. [NIST](#3-nist)
4. [CNCF / Kubernetes Security](#4-cncf--kubernetes-security)
5. [Other Standards Bodies](#5-other-standards-bodies)
6. [Industry Threat Reports](#6-industry-threat-reports)
7. [Threat-to-Observable Mapping](#7-threat-to-observable-mapping)

---

## 1. OWASP

### 1.1 OWASP Top 10 for LLM Applications 2025

**Source:** [OWASP GenAI Security Project](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
**Date:** Late 2024 (v2025)
**Authority:** Industry-standard, globally peer-reviewed

| ID | Risk | Kernel-Level Detectability |
|---|---|---|
| LLM01 | Prompt Injection | Low - application/LLM stream layer |
| LLM02 | Sensitive Information Disclosure | Medium - network egress + file access patterns |
| LLM03 | Supply Chain Vulnerabilities | Medium - file integrity, process lineage |
| LLM04 | Data and Model Poisoning | Low - requires application-layer validation |
| LLM05 | Improper Output Handling | Low - application layer |
| LLM06 | Excessive Agency | High - syscall patterns, tool invocations, privilege use |
| LLM07 | System Prompt Leakage | Low - application/network layer |
| LLM08 | Vector and Embedding Weaknesses | Low - application layer |
| LLM09 | Misinformation | None - semantic layer only |
| LLM10 | Unbounded Consumption | High - resource usage (CPU, memory, GPU, network I/O) |

**Key observations for kernel-level monitoring:**
- LLM06 (Excessive Agency) is the most directly observable: agents invoking tools manifest as process executions, file operations, and network calls at the syscall level
- LLM10 (Unbounded Consumption) maps directly to cgroup resource metrics
- LLM02 (Sensitive Information Disclosure) is partially detectable via network egress monitoring and file read patterns

### 1.2 OWASP Top 10 for Agentic Applications 2026

**Source:** [OWASP Agentic Security Initiative](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
**Date:** December 2025
**Authority:** Globally peer-reviewed, 100+ security researchers

| ID | Risk | Description | Kernel-Level Detectability |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Attackers alter agent objectives via malicious content in emails, PDFs, web content | Low - behavioral change detectable via anomalous tool usage patterns |
| ASI02 | Tool Misuse and Exploitation | Agents use legitimate tools unsafely due to manipulated input | High - observable as unexpected execve patterns, dangerous CLI args |
| ASI03 | Identity and Privilege Abuse | Credentials/tokens inherited by agents reused or escalated improperly | High - credential file access, privilege escalation syscalls |
| ASI04 | Agentic Supply Chain | Compromised tools, plugins, MCP servers fetched at runtime | High - new process execution, network fetches, file writes |
| ASI05 | Unexpected Code Execution | Agents generate/execute code, shell commands, scripts unsafely | High - execve, fork, clone syscalls for unexpected processes |
| ASI06 | Memory and Context Poisoning | Attackers poison agent memory, RAG databases, summaries | Low - application layer, partial via file/DB write monitoring |
| ASI07 | Insecure Inter-Agent Communication | Multi-agent messages lack auth/encryption/validation | Medium - network traffic analysis, TLS verification |
| ASI08 | Cascading Failures | Small errors propagate across planning, execution, memory | Medium - resource consumption spikes, error-retry loops |
| ASI09 | Human-Agent Trust Exploitation | Users over-trust agent recommendations | None - human behavioral layer |
| ASI10 | Rogue Agents | Compromised agents act harmfully while appearing legitimate | High - anomalous process trees, unexpected network connections |

**Key mitigations with kernel-level relevance:**
- Least agency: enforceable via seccomp profiles, Landlock LSM, capability restrictions
- Sandboxed execution: gVisor, microVMs, namespace isolation
- Argument validation: detectable via execve argument inspection
- Short-lived credentials: monitorable via credential file access patterns

### 1.3 Additional OWASP Publications

- **Agentic AI Threats & Mitigations Taxonomy** (February 2025) - first of its kind
- **AI Security Solutions Landscape for Agentic AI** - quarterly updates (Q3 2025, Q2 2026)
- **State of Agentic AI Security and Governance 1.0**
- **OWASP GenAI Data Security Risks & Mitigations 2026**

---

## 2. MITRE

### 2.1 MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

**Source:** [MITRE ATLAS](https://atlas.mitre.org/)
**Date:** v5.4.0 (February 2026)
**Authority:** MITRE Corporation, globally recognized threat knowledge base

**Framework scope:** 16 tactics, 84 techniques, 56 sub-techniques, 32 mitigations, 42 case studies

#### Complete Tactic List

| ID | Tactic | Kernel Observable |
|---|---|---|
| AML.TA0001 | Reconnaissance | Network probing patterns |
| AML.TA0002 | Resource Development | Process/file creation patterns |
| AML.TA0003 | Initial Access | Network connections, process spawning |
| AML.TA0004 | ML Model Access | File/API access patterns |
| AML.TA0005 | Execution | execve, fork, clone syscalls |
| AML.TA0006 | Persistence | File modifications, cron/systemd changes |
| AML.TA0007 | Privilege Escalation | setuid, capability changes, namespace manipulation |
| AML.TA0008 | Defense Evasion | Process hiding, log tampering |
| AML.TA0009 | Credential Access | File reads on credential stores |
| AML.TA0010 | Discovery | System enumeration commands |
| AML.TA0011 | Collection | File reads, clipboard access |
| AML.TA0012 | ML Attack Staging | Data file manipulation |
| AML.TA0013 | Exfiltration | Network egress patterns |
| AML.TA0014 | Impact | Data destruction, resource exhaustion |
| AML.TA0015 | Command and Control | Network connection patterns |

#### Key AI Agent-Specific Techniques

| ID | Technique | Description | Detection Layer |
|---|---|---|---|
| AML.T0051 | Prompt Injection | Direct/indirect prompt manipulation | LLM stream |
| AML.T0051.001 | Direct Prompt Injection | Attacker directly injects into prompt | LLM stream |
| AML.T0051.002 | Indirect Prompt Injection | Injection via external data sources | LLM stream + network |
| AML.T0058 | AI Agent Context Poisoning | Corrupting agent memory/context | Application + file I/O |
| AML.T0059 | Activation Triggers | Backdoor triggers in model behavior | Application layer |
| AML.T0060 | Data from AI Services | RAG database data retrieval exploitation | Application + file I/O |
| AML.T0061 | AI Agent Tools | Exploiting agent tool access | Kernel (execve, file ops) |
| AML.T0062 | Exfiltration via AI Agent Tool | Using tool invocations to exfiltrate data | Kernel + network |
| AML.T0096 | AI Service API | C2 via legitimate AI service APIs | Network |
| AML.T0098 | AI Agent Tool Credential Harvesting | Retrieving credentials from agent tools | Kernel (file reads) |
| AML.T0099 | AI Agent Tool Data Poisoning | Placing malicious content where agents invoke | Application + file I/O |
| AML.T0100 | AI Agent Clickbait | Luring AI browsers into unintended actions | Application layer |
| AML.T0101 | Data Destruction via AI Agent Tool | Using tool capabilities to destroy data | Kernel (unlink, rmdir) |
| - | Publish Poisoned AI Agent Tool | Malicious MCP tools appearing safe | Application + kernel |
| - | Escape to Host | Agent sandboxing bypass | Kernel (namespace, mount) |
| - | Modify AI Agent Configuration | Persistence via config changes | Kernel (file writes) |
| AML.T0020 | Poison Training Data | Malicious training data introduction | File I/O |

**Note:** ~70% of ATLAS mitigations map to existing security controls, indicating significant overlap with traditional security monitoring.

### 2.2 MITRE ATLAS OpenClaw Investigation (February 2026)

**Source:** [MITRE OpenClaw Investigation](https://www.mitre.org/news-insights/publication/mitre-atlas-openclaw-investigation)
**Date:** February 9, 2026
**Authority:** MITRE Center for Threat-Informed Defense

Key findings:
- Seven new techniques unique to OpenClaw discovered
- Common techniques: direct/indirect LLM prompt injection, AI agent tool invocation, modifying agentic configuration
- CVE-2026-25253: One-Click RCE vulnerability via crafted malicious webpage link (millisecond execution)
- First in a series examining agentic AI vulnerability landscapes

### 2.3 SesameOp Case Study (AML.CS0042)

Novel backdoor leveraging OpenAI Assistants API for C2, blending malicious activity into legitimate AI workflows. Demonstrates how agentic AI infrastructure creates C2 channels evading conventional network detection.

### 2.4 MITRE ATT&CK Relevance

Traditional ATT&CK techniques applicable to AI agent attacks:
- T1059 (Command and Scripting Interpreter) - agents executing generated code
- T1078 (Valid Accounts) - credential theft via agent tool access
- T1048 (Exfiltration Over Alternative Protocol) - data exfil via AI API calls
- T1190 (Exploit Public-Facing Application) - attacking exposed AI endpoints
- T1611 (Escape to Host) - container escape from agent sandbox

---

## 3. NIST

### 3.1 AI Risk Management Framework (AI RMF 1.0) - NIST AI 100-1

**Source:** [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
**Date:** January 26, 2023
**Authority:** U.S. federal standard

Four core functions: GOVERN, MAP, MEASURE, MANAGE

Trustworthiness characteristics: valid/reliable, safe, secure/resilient, accountable/transparent, explainable/interpretable, privacy-enhanced, fair

**Relevance to kernel-level monitoring:**
- MEASURE function requires continuous assessment of AI system behavior
- MANAGE function requires risk response and recovery capabilities
- Security/resilience characteristics map to runtime monitoring requirements

### 3.2 Generative AI Profile (NIST AI 600-1)

**Source:** [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
**Date:** July 26, 2024
**Authority:** U.S. federal guidance

Enumerates 12 risks unique to or exacerbated by generative AI: hallucinations, data leakage, copyright concerns, harmful bias, misuse (disinformation, cybersecurity).

### 3.3 NIST AI 800-4: Challenges to Monitoring Deployed AI Systems

**Source:** [NIST AI 800-4](https://www.nist.gov/news-events/news/2026/03/new-report-challenges-monitoring-deployed-ai-systems)
**Date:** March 2026
**Authority:** NIST CAISI

Six monitoring categories identified:

| Category | Kernel-Level Relevance |
|---|---|
| Functionality Monitoring | Low - application metrics |
| Operational Monitoring | High - resource usage, uptime, latency |
| Human Factors Monitoring | None |
| Security Monitoring | High - syscalls, network, file access |
| Compliance Monitoring | Medium - audit logging |
| Large-Scale Impacts Monitoring | None |

Key challenges:
- Absence of standardized monitoring tools
- Difficulty scaling human oversight during rapid AI rollouts
- Non-deterministic nature of AI agents makes rule-based monitoring insufficient
- Tension between competitive pressures and necessary oversight

### 3.4 SP 800-53 Control Overlays for Securing AI Systems (COSAiS)

**Source:** [NIST COSAiS](https://csrc.nist.gov/projects/cosais)
**Date:** Concept paper August 2025; ongoing development
**Authority:** NIST CSRC

Five proposed use cases:
1. Adapting and Using Generative AI (LLM applications)
2. Using and Fine-Tuning Predictive AI
3. **Using AI Agent Systems - Single Agent**
4. **Using AI Agent Systems - Multi-Agent**
5. Security Controls for AI Developers

Use cases 3 and 4 directly address agent security with SP 800-53 control overlays.

### 3.5 NIST AI Agent Standards Initiative

**Source:** [NIST AI Agent Standards Initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative)
**Date:** February 2026
**Authority:** NIST CAISI + NSF

Three pillars:
1. Industry-led agent standards development
2. Community-led open source protocol development
3. Research in AI agent security and identity

Key security challenges identified:
- Autonomous agent actions require oversight mechanisms
- Dynamic tool-switching defeats static policy enforcement
- Information retention enables data poisoning attacks
- Non-deterministic behavior resists rule-based security controls

### 3.6 NIST SP 800-190 (Container Security)

**Source:** [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final)
**Authority:** NIST

While not AI-specific, provides foundational container security guidance applicable to AI agent workloads:
- Runtime protection via anomalous behavior detection
- Image vulnerability scanning
- Host OS hardening
- Network segmentation

### 3.7 Cybersecurity Framework Profile for AI (NIST IR 8596)

**Source:** [NIST IR 8596](https://csrc.nist.gov/pubs/ir/8596/iprd)
**Date:** 2025 (initial public review draft)
**Authority:** NIST

Maps the Cybersecurity Framework to AI-specific risks and controls.

---

## 4. CNCF / Kubernetes Security

### 4.1 Certified Kubernetes AI Conformance Program

**Source:** [CNCF Announcement](https://www.cncf.io/announcements/2025/11/11/cncf-launches-certified-kubernetes-ai-conformance-program-to-standardize-ai-workloads-on-kubernetes/)
**Date:** November 2025
**Authority:** CNCF

Technical baseline for AI workloads:
- Dynamic Resource Allocation for accelerator management
- Volume handling for large datasets
- Job-level networking for distributed training
- Gang scheduling for resource deadlock prevention
- Expanded to include agentic workload validation aligned with Kubernetes v1.35

### 4.2 Zero-Trust AI Blueprint for Kubernetes

**Source:** [CNCF Blog](https://www.cncf.io/blog/2025/10/10/a-blueprint-for-zero-trust-ai-on-kubernetes/)
**Date:** October 2025
**Authority:** CNCF community

Security architecture layers:

| Layer | Controls | Observable At |
|---|---|---|
| Ingress | TLS termination via Gateway API | Network |
| Network Segmentation | NetworkPolicies, Calico/Cilium | Network + kernel (eBPF) |
| Egress | NAT, egress gateways, IP-based API restrictions | Network + kernel |
| Identity | Workload identity, stable pod IPs, cloud IAM | Application + kernel |
| Observability | OpenTelemetry, Prometheus, flow logs | All layers |

### 4.3 Runtime Security Tools for AI Workloads

#### Falco

**Source:** [Falco Project](https://falco.org/)
**Authority:** CNCF graduated project

- eBPF-based syscall interception at kernel level
- Monitors every system call from every process/container
- No agent-side instrumentation required
- Real-time alerting based on custom rules
- Directly applicable to AI agent monitoring

#### Sysdig Research on AI Coding Agents

**Source:** [Sysdig Blog](https://webflow.sysdig.com/blog/ai-coding-agents-are-running-on-your-machines-do-you-know-what-theyre-doing)
**Date:** 2025
**Authority:** Sysdig Threat Research Team

Observable syscall patterns from AI agents:
- **Process spawning:** 64 execve events in 10-second windows
- **Shell execution:** disposable bash shells spawning for single commands
- **Network connections:** multiple outbound HTTPS connections between iterations
- **File I/O:** reading credential files and config directories

Agent-specific process fingerprints:
- Claude Code: bundled Bun binary at installation-specific paths
- Gemini CLI: Node.js interpreter execution
- Codex CLI: standalone Rust binary

Four detection patterns:
1. Installation detection via package managers
2. Unauthorized credential access (monitoring ~/.claude/, ~/.gemini/, ~/.codex/)
3. Safety control bypass via unsafe command-line flags
4. Sensitive file reads by agent processes

**Key finding:** "An application-level sandbox cannot protect against threats that operate at the same privilege level as the sandbox itself." Kernel-level observation is fundamental.

#### Kubescape 4.0

**Source:** [CNCF Blog](https://www.cncf.io/blog/2026/03/26/announcing-kubescape-4-0-enterprise-stability-meets-the-ai-era/)
**Date:** March 2026
**Authority:** CNCF

KAgent-native plugin allowing AI assistants to analyze Kubernetes security posture directly.

### 4.4 Kernel-Level Sandboxing for AI Agents

**Sources:** Multiple industry publications, 2025-2026

| Technology | Mechanism | Protection Level |
|---|---|---|
| Seccomp | Syscall filtering | Blocks specific system calls |
| Linux Landlock | Filesystem access control | Restricts file/dir access per-process |
| gVisor | User-space kernel (Sentry) | Intercepts syscalls before host kernel |
| MicroVMs (Firecracker) | Lightweight VM isolation | Full kernel isolation |
| Linux namespaces | Process/network/mount isolation | Container-level isolation |
| eBPF (Falco/Tetragon) | Kernel event observation | Detection and audit |

**Critical insight:** Standard Docker containers share the host kernel. Running untrusted LLM-generated code in a permissive container is trivially escapable. gVisor or microVM isolation is recommended for AI agent workloads.

---

## 5. Other Standards Bodies

### 5.1 ENISA (EU Agency for Cybersecurity)

#### AI Cybersecurity Challenges Report

**Source:** [ENISA](https://www.enisa.europa.eu/publications/artificial-intelligence-cybersecurity-challenges)
**Authority:** EU member states cybersecurity agency

Provides AI threat landscape taxonomy covering:
- AI-specific attack vectors
- Vulnerability assessment methodology
- Mapping threats to countermeasures

#### Threat Landscape 2025

**Source:** [ENISA Threat Landscape 2025](https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025)
**Date:** October 2025
**Authority:** ENISA

Analysis of 4,875 cybersecurity incidents. Key AI findings:
- 80%+ of phishing campaigns use AI-generated content
- Emergence of malicious AI systems (Xanthorox AI)
- AI supply chain attacks: poisoned ML models, malicious PyPI packages, backdoored coding assistant configs
- AI-enabled adversary attacks surged 89% year-over-year

### 5.2 ISO/IEC 42001:2023 (AI Management System)

**Source:** [ISO 42001](https://www.iso.org/standard/42001)
**Date:** 2023
**Authority:** ISO/IEC international standard

Key monitoring requirements:
- Continuous monitoring via automated logging, anomaly detection, compliance dashboards
- Performance Evaluation (Clause 9): continuous monitoring and auditing of AI systems
- Plan-Do-Check-Act methodology

Security controls:
- Data governance (source quality, lineage, privacy)
- Model development (secure practices, adversarial testing, explainability)
- Operations (runtime monitoring, incident response, change management)
- Governance (roles, oversight, ethics, transparency)

### 5.3 EU AI Act

**Source:** [EU AI Act](https://artificialintelligenceact.eu/)
**Date:** Fully applicable August 2, 2026
**Authority:** EU regulation (binding law)

#### Article 12 - Record-Keeping (Logging Requirements)

High-risk AI systems shall technically allow for automatic recording of events (logs) over the system lifetime. Logging shall enable:
- Identifying situations presenting risk
- Facilitating post-market monitoring (Article 72)
- Monitoring operation of high-risk AI systems

#### Article 72 - Post-Market Monitoring

Providers must:
- Establish documented post-market monitoring system
- Actively and systematically collect, document, and analyze relevant data
- Evaluate continuous compliance throughout system lifetime
- Base monitoring on a formal post-market monitoring plan

#### Article 9 - Risk Management

Documented, ongoing risk management process covering entire AI lifecycle: design through post-market monitoring. Must identify and evaluate known and foreseeable risks to health, safety, and fundamental rights.

**Kernel-level relevance:** Article 12's automatic event recording requirement maps directly to syscall-level audit logging. The requirement for continuous compliance monitoring supports runtime security monitoring implementations.

### 5.4 Cloud Security Alliance (CSA)

#### CSAI Foundation

**Source:** [CSA CSAI Launch](https://cloudsecurityalliance.org/press-releases/2026/03/23/csa-securing-the-agentic-control-plane)
**Date:** March 2026
**Authority:** CSA (501(c)3 non-profit)

Strategic mission: "Securing the Agentic Control Plane" covering identity, authorization, orchestration, runtime behavior, and trust assurance for autonomous AI ecosystems.

Six strategic programs for 2026:
1. AI Risk Observatory - continuous monitoring and threat intelligence for agentic AI
2. Observability of in-the-wild agentic activity across OpenClaw and MCP ecosystems
3. Agentic Best Practices - full lifecycle guidance for secure agentic implementation
4. (Three additional programs not detailed in sources)

#### State of AI Security and Governance Report

**Source:** [CSA Report](https://cloudsecurityalliance.org/artifacts/the-state-of-ai-security-and-governance)
**Date:** 2025
**Authority:** CSA, commissioned by Google

Data-driven analysis of enterprise GenAI and agentic AI adoption risks and governance structures.

### 5.5 International AI Safety Report 2026

**Source:** [International AI Safety Report](https://internationalaisafetyreport.org/publication/international-ai-safety-report-2026)
**Date:** February 2026
**Authority:** 100+ AI experts, backed by 30+ countries, led by Yoshua Bengio

Key findings on agentic AI:
- AI agents pose heightened risks due to autonomous action
- AI agent identified 77% of vulnerabilities in real software in competition
- State-associated attackers actively using AI in operations
- Sophisticated attackers can often bypass current defenses
- Real-world effectiveness of many safeguards is uncertain
- Number of companies publishing Frontier AI Safety Frameworks has more than doubled since 2025

---

## 6. Industry Threat Reports

### 6.1 Anthropic: First AI-Orchestrated Cyber Espionage Campaign

**Source:** [Anthropic Report](https://www.anthropic.com/news/disrupting-AI-espionage)
**Date:** Detected September 2025, published November 2025
**Authority:** Anthropic (AI developer, direct incident response)

**Threat Actor:** GTG-1002 (Chinese state-sponsored, high confidence)
**Tool:** Claude Code with autonomous agentic orchestration
**Targets:** ~30 global targets (tech, finance, chemical manufacturing, government agencies)
**Success rate:** Small number of infiltrations succeeded

**Attack methodology:**
- Role-play deception: operators claimed to be employees of legitimate cybersecurity firms
- AI performed 80-90% of all operational tasks autonomously
- Human operators provided only 4-6 critical decision points per campaign
- At peak, thousands of API requests per second (impossible speed for human hackers)
- Full kill chain: reconnaissance, exploitation, credential harvesting, lateral movement, data exfiltration

**Kernel-level observables (if monitored):**
- Rapid process spawning patterns
- Network scanning / port probing from agent process
- Credential file access patterns
- Lateral movement indicators (SSH, RDP connections from unexpected sources)
- Data staging and exfiltration via unusual egress

### 6.2 OpenClaw Security Crisis (2026)

**Source:** [Multiple incident reports](https://adversa.ai/blog/openclaw-attacks-real-scenarios-owasp-mitre-csa-defense-guide/)
**Date:** Early 2026

- 135,000+ GitHub stars, viral open-source AI agent
- Multiple critical vulnerabilities and malicious marketplace exploits
- 21,000+ exposed instances
- CVE-2026-25253: One-Click RCE via crafted webpage (millisecond execution)
- First major AI agent security crisis of 2026

### 6.3 OpenAI Plugin Supply Chain Attack (2026)

Compromised agent credentials harvested from 47 enterprise deployments. Attackers used credentials to access customer data, financial records, and proprietary code for six months before discovery.

### 6.4 Shadow Escape Exploit (2025)

Discovered by Operant AI: zero-click exploit targeting agents built on Model Context Protocol (MCP).

### 6.5 Google DeepMind Cybersecurity Framework

Novel evaluation framework examining end-to-end attack chains, identifying gaps in AI threat evaluation, enabling AI-enabled adversary emulation for red teaming.

### 6.6 Red Team Research Findings

Joint research (OpenAI, Anthropic, Google DeepMind, October 2025):
- Examined 12 published defenses against prompt injection and jailbreaking
- Using adaptive attacks, bypassed defenses with >90% success rate for most
- Significant gap between reported defense performance and real-world resilience

### 6.7 Adversa AI Security Incidents Report 2025

**Source:** [Adversa AI](https://adversa.ai/blog/adversa-ai-unveils-explosive-2025-ai-security-incidents-report-revealing-how-generative-and-agentic-ai-are-already-under-attack/)

- Prompt-based exploits: 35.3% of all documented AI incidents (most common)
- Shadow AI breaches cost average $670,000 more than traditional incidents
- Affect roughly 1 in 5 organizations

### 6.8 Trend Micro State of AI Security Report (H1 2025)

**Source:** [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/threat-landscape/trend-micro-state-of-ai-security-report-1h-2025)

Reports on AI ecosystem vulnerabilities and emerging threat patterns.

---

## 7. Threat-to-Observable Mapping

### 7.1 Comprehensive Mapping: Threat --> Detection Layer

```
LEGEND:
  K = Kernel (syscalls, eBPF, process tree, cgroups)
  N = Network (packet inspection, flow analysis, DNS, TLS)
  A = Application (logs, API calls, business logic)
  L = LLM Stream (token-level inspection, prompt/response analysis)
```

#### Agent Manipulation Threats

| Threat | OWASP | MITRE | K | N | A | L | Kernel Observables |
|---|---|---|---|---|---|---|---|
| Prompt Injection | LLM01, ASI01 | AML.T0051 | - | - | x | X | None directly; effects visible as anomalous tool calls |
| Agent Goal Hijack | ASI01 | AML.T0058 | o | - | x | X | Deviation in process execution patterns |
| Context/Memory Poisoning | ASI06 | AML.T0058,T0099 | o | - | X | x | File writes to memory/RAG stores |
| Rogue Agent | ASI10 | - | X | X | x | x | Anomalous process trees, unexpected network connections |

#### Tool and Execution Threats

| Threat | OWASP | MITRE | K | N | A | L | Kernel Observables |
|---|---|---|---|---|---|---|---|
| Tool Misuse | ASI02 | AML.T0061 | X | o | x | - | Unexpected execve args, dangerous CLI params |
| Unexpected Code Execution | ASI05 | AML.TA0005 | X | - | x | - | execve/fork/clone for unexpected processes, shell spawns |
| Container/Sandbox Escape | - | Escape to Host | X | - | o | - | setns, mount, unshare syscalls, namespace changes |
| Data Destruction | - | AML.T0101 | X | - | o | - | unlink, rmdir, truncate on critical files |
| Poisoned Tool Installation | ASI04 | Publish Poisoned Tool | X | X | x | - | New binary execution, package manager activity |

#### Credential and Identity Threats

| Threat | OWASP | MITRE | K | N | A | L | Kernel Observables |
|---|---|---|---|---|---|---|---|
| Credential Harvesting | ASI03 | AML.T0098 | X | - | x | - | File reads on ~/.ssh/, ~/.aws/, /etc/shadow, token files |
| Privilege Escalation | ASI03 | AML.TA0007 | X | - | o | - | setuid, capability manipulation, namespace changes |
| Identity Abuse | ASI03 | - | o | X | X | - | Token file access, unexpected API auth |

#### Data Exfiltration Threats

| Threat | OWASP | MITRE | K | N | A | L | Kernel Observables |
|---|---|---|---|---|---|---|---|
| Sensitive Info Disclosure | LLM02 | AML.T0062 | o | X | x | X | Large file reads followed by network sends |
| Exfil via Agent Tools | - | AML.T0062 | X | X | x | - | execve for data transfer tools, network egress spikes |
| C2 via AI API | - | AML.T0096 | - | X | x | - | Anomalous API call patterns, beaconing |

#### Supply Chain Threats

| Threat | OWASP | MITRE | K | N | A | L | Kernel Observables |
|---|---|---|---|---|---|---|---|
| Model/Data Poisoning | LLM04 | AML.T0020 | o | X | X | - | Write patterns to model/data directories |
| Supply Chain Compromise | LLM03, ASI04 | - | X | X | x | - | Unexpected downloads, new binary execution, file integrity changes |
| MCP Server Compromise | ASI04 | Publish Poisoned Tool | X | X | x | - | New network listeners, unexpected process execution |

#### Resource and Availability Threats

| Threat | OWASP | MITRE | K | N | A | L | Kernel Observables |
|---|---|---|---|---|---|---|---|
| Unbounded Consumption | LLM10 | - | X | o | x | - | CPU/memory/GPU cgroup metrics, process count |
| Cascading Failures | ASI08 | - | X | o | x | - | Error-retry loops, resource spikes, rapid fork patterns |
| Denial of Service | - | AML.TA0014 | X | X | o | - | Resource exhaustion, process count explosion |

```
KEY: X = primary detection layer, x = secondary/supporting, o = partial/indirect, - = not applicable
```

### 7.2 Kernel-Level Detection Priority Matrix

Threats ranked by kernel-level detectability (highest first):

| Priority | Threat Category | Key Syscalls/Observables | Detection Confidence |
|---|---|---|---|
| 1 | Container/Sandbox Escape | setns, mount, unshare, pivot_root, ptrace | Very High |
| 2 | Unexpected Code Execution | execve, fork, clone with unexpected process trees | Very High |
| 3 | Credential File Access | open/openat on credential paths | High |
| 4 | Data Destruction | unlink, rmdir, truncate on non-temp paths | High |
| 5 | Tool Misuse (dangerous args) | execve argument inspection | High |
| 6 | Privilege Escalation | setuid, capset, prctl(PR_SET_*) | High |
| 7 | Resource Exhaustion | cgroup metrics, process count, OOM events | High |
| 8 | Data Exfiltration | sendto/sendmsg following large read patterns | Medium |
| 9 | Supply Chain (runtime) | execve of new binaries, dlopen of new libraries | Medium |
| 10 | Network Reconnaissance | connect/sendto to scanning patterns | Medium |
| 11 | Agent Process Anomalies | execve frequency, process tree depth/breadth | Medium |
| 12 | Persistence Mechanisms | file writes to cron, systemd, .bashrc, agent configs | Medium |

### 7.3 Detection Architecture by Layer

```
+------------------------------------------------------------------+
|                    LLM STREAM LAYER                               |
|  - Token-level prompt/response inspection                        |
|  - Prompt injection detection                                    |
|  - Sensitive data in output detection                             |
|  - Goal alignment verification                                   |
|  - System prompt leak detection                                   |
+------------------------------------------------------------------+
|                    APPLICATION LAYER                              |
|  - API call logging and anomaly detection                         |
|  - Tool invocation validation                                     |
|  - Agent memory/context integrity checks                          |
|  - Business logic guardrails                                      |
|  - Inter-agent message authentication                             |
|  - RAG/vector DB access controls                                  |
+------------------------------------------------------------------+
|                    NETWORK LAYER                                  |
|  - TLS inspection of agent communications                         |
|  - DNS query monitoring for C2 detection                          |
|  - Egress traffic analysis (volume, destination, protocol)        |
|  - Network policy enforcement (Calico/Cilium)                     |
|  - API endpoint access patterns                                   |
|  - Inter-agent communication encryption verification              |
+------------------------------------------------------------------+
|                    KERNEL LAYER                                   |
|  - Syscall monitoring (eBPF/Falco/Tetragon)                      |
|  - Process tree analysis (unexpected children, depth)             |
|  - File access patterns (credential files, config files)          |
|  - Namespace/cgroup manipulation detection                        |
|  - Resource consumption tracking (CPU, memory, I/O)               |
|  - Seccomp profile enforcement                                    |
|  - Landlock filesystem access control                             |
|  - Capability usage monitoring                                    |
|  - Mount/unmount operations                                       |
|  - execve argument and binary hash verification                   |
+------------------------------------------------------------------+
```

### 7.4 Recommended Detection Rules for Containerized AI Agent Workloads

Based on cross-referencing all frameworks, the following are highest-priority detection rules:

**Critical (must-have):**
1. Unexpected process execution from agent container (execve not matching baseline)
2. Container escape indicators (setns, nsenter, mount of host paths)
3. Credential file access (open/openat on ~/.ssh, ~/.aws, /etc/shadow, /var/run/secrets)
4. Shell spawning from agent process (bash/sh/zsh child of agent binary)
5. Network connections to unexpected destinations
6. File writes outside designated workspace paths
7. Privilege escalation syscalls (setuid, capset)
8. Resource consumption exceeding thresholds (cgroup OOM, CPU throttle)

**High (should-have):**
9. Rapid process spawning (>N execve/s from single container)
10. Data staging patterns (large reads followed by network writes)
11. Package manager execution within agent container
12. Agent configuration file modifications
13. DNS queries for unexpected domains
14. Process tree depth/breadth anomalies

**Medium (nice-to-have):**
15. System enumeration commands (whoami, hostname, ifconfig, cat /etc/passwd)
16. Clipboard or X11 access from agent container
17. Outbound connection beaconing patterns
18. Temporary file creation patterns indicating attack staging

---

## Appendix A: Standards Cross-Reference Matrix

| Framework | Focus | Agent-Specific | Monitoring Guidance | Kernel-Level | Container-Specific |
|---|---|---|---|---|---|
| OWASP LLM Top 10 2025 | LLM risks | Partial (LLM06) | General | Indirect | No |
| OWASP Agentic Top 10 2026 | Agent risks | Yes (full) | Detailed | Indirect | Partial |
| MITRE ATLAS v5.4.0 | AI threat TTPs | Yes (14+ techniques) | Detection per technique | Partial | No |
| NIST AI RMF 1.0 | Risk management | No | Framework-level | No | No |
| NIST AI 600-1 | GenAI profile | No | Risk-specific | No | No |
| NIST AI 800-4 | Monitoring challenges | Yes (mentioned) | Categories defined | No | No |
| NIST COSAiS | SP 800-53 overlays | Yes (Use Cases 3,4) | Control-specific | Via SP 800-53 | Via SP 800-190 |
| NIST Agent Standards | Agent standards | Yes (primary) | In development | TBD | TBD |
| EU AI Act | Regulation | No (applies to all) | Articles 12, 72 | Logging mandated | No |
| ISO/IEC 42001 | AIMS | No (general AI) | Clause 9 | No | No |
| ENISA TL 2025 | Threat landscape | Partial | General | No | No |
| CSA/CSAI | Cloud/AI security | Yes (agentic control plane) | In development | TBD | TBD |
| CNCF K8s AI | K8s AI workloads | Partial | Conformance testing | Via Falco/eBPF | Yes |
| Intl AI Safety 2026 | Global AI safety | Yes | Policy-level | No | No |

## Appendix B: Key Source Documents

### OWASP
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [AI Security Solutions Landscape Q2 2026](https://genai.owasp.org/resource/ai-security-solutions-landscape-for-agentic-ai-q2-2026/)
- [State of Agentic AI Security and Governance 1.0](https://genai.owasp.org/resource/state-of-agentic-ai-security-and-governance-1-0/)

### MITRE
- [MITRE ATLAS](https://atlas.mitre.org/)
- [MITRE ATLAS OpenClaw Investigation](https://www.mitre.org/news-insights/publication/mitre-atlas-openclaw-investigation)
- [Zenity & MITRE ATLAS AI Agent Techniques](https://zenity.io/blog/current-events/mitre-atlas-ai-security)
- [MITRE ATT&CK](https://attack.mitre.org/)

### NIST
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1 GenAI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [NIST AI 800-4 Monitoring Challenges](https://www.nist.gov/news-events/news/2026/03/new-report-challenges-monitoring-deployed-ai-systems)
- [NIST COSAiS](https://csrc.nist.gov/projects/cosais)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative)

### CNCF / Kubernetes
- [CNCF Kubernetes AI Conformance Program](https://www.cncf.io/announcements/2025/11/11/cncf-launches-certified-kubernetes-ai-conformance-program-to-standardize-ai-workloads-on-kubernetes/)
- [Zero-Trust AI Blueprint for Kubernetes](https://www.cncf.io/blog/2025/10/10/a-blueprint-for-zero-trust-ai-on-kubernetes/)
- [Falco Project](https://falco.org/)
- [Sysdig AI Agent Monitoring Research](https://webflow.sysdig.com/blog/ai-coding-agents-are-running-on-your-machines-do-you-know-what-theyre-doing)

### EU / ENISA / ISO
- [EU AI Act](https://artificialintelligenceact.eu/)
- [EU AI Act Article 12 - Record-Keeping](https://artificialintelligenceact.eu/article/12/)
- [EU AI Act Article 72 - Post-Market Monitoring](https://artificialintelligenceact.eu/article/72/)
- [ENISA Threat Landscape 2025](https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025)
- [ENISA AI Cybersecurity Challenges](https://www.enisa.europa.eu/publications/artificial-intelligence-cybersecurity-challenges)
- [ISO/IEC 42001](https://www.iso.org/standard/42001)

### CSA
- [CSAI Foundation Launch](https://cloudsecurityalliance.org/press-releases/2026/03/23/csa-securing-the-agentic-control-plane)
- [State of AI Security and Governance](https://cloudsecurityalliance.org/artifacts/the-state-of-ai-security-and-governance)

### Industry Reports
- [Anthropic: Disrupting AI-Orchestrated Espionage](https://www.anthropic.com/news/disrupting-AI-espionage)
- [International AI Safety Report 2026](https://internationalaisafetyreport.org/publication/international-ai-safety-report-2026)
- [Adversa AI 2025 Incidents Report](https://www.adversa.ai/top-ai-security-incidents-report-2025-edition/)
- [ARMO AI Agent Escape Detection](https://www.armosec.io/blog/ai-agent-escape-detection/)
- [Google DeepMind Cyberattack Evaluation Framework](https://arxiv.org/html/2503.11917v3)
