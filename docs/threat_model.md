# Threat Model

## Adversary Definition
The adversary can inject arbitrary text into the agent's context via three vectors: (1) direct user input, (2) poisoned documents retrieved via RAG, and (3) social engineering through authority impersonation. The adversary cannot break HMAC-SHA256 attestation tokens or directly modify enclave state.

## Security Property (Execution Integrity)
For all tool executions T in an agentic workflow W:
T executes IFF:
  Attest(chain(T)) = VALID
  AND OPA_Policy(T) = PERMIT

No tool execution completes unless its causal chain originates from a verified, policy-compliant agent state.

## Security Property (Agentic Non-Interference)
Let W(C) be the set of tool calls executed under context C.
Let C_clean be a context without injected adversarial content.
Let C_attack differ from C_clean only by injected content.

W satisfies non-interference iff:
     W(C_clean) = W(C_attack)

Operationally, our runtime enforcement approximates this property with per-call policy checks, attestation integrity, and sequence-aware constraints across tool-call chains.

## Theorem 1 (Enforcement Completeness)
Under ZT-AgentShield enforcement, no restricted tool t in T_R executes unless all three conditions hold:
     (1) Attest(chain(e)) = VALID
     (2) Policy(t, ctx) = PERMIT
     (3) Seq(hist, t) = PERMIT

Proof sketch: The enforcement middleware is the sole code path to tool execution. All three checks are evaluated synchronously before function invocation. If any check returns DENY, control returns a blocked verdict and the tool function is not called. Therefore, restricted tool execution implies all three checks passed. QED.

Corollary 1 (A5 Necessity of Sequence Enforcement)
Any system enforcing only condition (2) is insufficient against semantic composition attacks.

Proof sketch: Let t1 and t2 be individually permitted tools whose composition achieves restricted goal g.
Condition (2) permits t1 and t2 independently.
Only condition (3) captures the restricted composition.
Therefore sequence enforcement is necessary for this class.
QED.

## Why Existing Systems Fail
Vanilla LangGraph authenticates the communication channel (transport layer) but does not verify execution integrity (computation layer). mTLS confirms "who sent this message" but cannot confirm "was the sending agent uncompromised when it generated this tool call." This distinction is the core gap our system addresses.

Despite the severity of this vulnerability, execution-boundary enforcement for agentic systems remains under-addressed for three reasons: (1) agentic LLM deployment is recent, with production pipelines emerging only in 2024-2025; (2) transport-layer security creates a false sense of coverage, where mTLS is often assumed to imply execution integrity; and (3) semantic composition attacks require reasoning over tool sequences, a frame that is uncommon in classical per-request access control deployments.

Input-layer guardrails (e.g., self-check classification) inspect user-facing prompts before model execution. By design, they do not enforce execution-boundary integrity over content that arrives after input checks, such as retrieved documents or tool-result payloads. In split-format tests where user queries are clean and malicious directives arrive in injected post-check context, the unprotected LLM reaches 100% ASR on A2 and A4 (n=10). This is an architectural property of input-only defenses rather than an implementation bug in any single framework.

## Attack Scenarios
A1 - Direct: Attacker instructs agent directly to call dangerous tools via explicit override commands.
A2 - Indirect: Attacker embeds malicious instructions in a document retrieved by RAG pipeline.
A3 - Escalation: Attacker impersonates authority figure to authorize dangerous tool execution.
A4 - Multi-hop: Attacker injects malicious directives via prior tool output and causes unsafe downstream action.
A5 - Semantic composition: Attacker chains permitted tools (e.g., read then external report) to exfiltrate data.
B1 - Benign: Legitimate user requests permitted tool. System must NOT block this (false positive test).

## Limitations
The intent-aware mitigation uses a static keyword list and is vulnerable to adversarial embedding: an attacker aware of the signal vocabulary can include authorization keywords in an injection prompt to bypass per-call policy checks. This attack requires knowledge of deployment-specific keyword settings and creates a hybrid attack that combines A1-style prompt injection with mitigation evasion. We treat this mitigation as an operator-friction reduction mechanism for legitimate workflows, not as a standalone security boundary.

The dependency checker is intentionally conservative and still lexical in the current prototype. It can miss paraphrases such as "alice@example.com" rewritten as "user email", encoded references such as "sk-12345" rewritten as "API key", and multi-step summaries where the original token form is lost across intermediate tool outputs. Those failures are acceptable only as explicit limitations, not as security guarantees.
