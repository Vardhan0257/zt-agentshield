# Key Findings

## Finding 1 - Indirect RAG Injection (A2): FULLY PREVENTED
Baseline attack success rate: 100% (20/20 executions)
Protected attack success rate: 0% (0/20 executions)
Attack reduction: 100%

The baseline agent consistently executes exfiltrate_secrets when the tool call is embedded in a retrieved document, confirming that LangGraph provides no execution-layer defense against indirect prompt injection. The protected system blocks all 20 attempts via policy enforcement (POLICY_DENIED), demonstrating complete prevention of this attack class.

## Finding 2 - Benign Request (B1): NO FALSE POSITIVES
Baseline success: 100% (20/20 permitted)
Protected success: 100% (20/20 permitted)
False positive rate: 0%

The enforcement layer correctly permits all legitimate read_users requests, confirming that zero-trust policy enforcement does not degrade normal operational capability.

## Finding 3 - LLM-Level Refusal (A1, A3)
The local LLM model refused explicit attack prompts at the model level before tool execution was attempted. This represents a defense-in-depth finding: model-level safety + execution-layer enforcement provides layered protection. This is documented as an observation, not a failure of our system.

## Overhead
Mean enforcement overhead: 3.3ms (A2), <13ms across runs. This is acceptable for production agentic workflows where inference latency dominates (typically 500ms-2s).

## Ablation Discussion (Attestation Contribution)
The attestation layer's contribution is context-dependent. In single-agent scenarios, per-call policy is sufficient and attestation provides redundant verification. In multi-agent scenarios (MA1, MA2), attestation is the load-bearing component: a compromised upstream agent produces an invalid token that propagates denial downstream regardless of policy state. The three-layer design is therefore appropriate for general multi-agent deployment, with single-agent deployments benefiting primarily from policy enforcement.

## Claim Tightening (Paper Text)
Abstract language:
"ZT-AgentShield reduces false-positive rate from 33.3% to 0% via intent-aware heuristic mitigation, with the caveat that static keyword lists are bypassable by adaptive adversaries (A6)."

Section 5 language after FPR table:
"A6 (mitigation evasion) demonstrates that embedding authorization keywords in an attack prompt bypasses the keyword mitigation with 100% ASR, confirming that intent-aware mitigation reduces operational false positives but does not constitute a security boundary."

Contributions language:
"An empirical evaluation across architecturally distinct models spanning large parameter-scale differences, showing model-agnostic effectiveness of execution-boundary enforcement and exposing model-specific variance in composition behavior."

## A5 Cross-Model Observation (Llama-3.3-70B)
Llama-3.3-70B exhibited partial self-resistance to A5 by producing only the first call (read_users) and halting, rather than executing the full read-then-send composition. This behavior was consistent in the reported 10-trial run. Qwen3-32B did not exhibit this behavior and reached 100% baseline ASR on A5. ZT-AgentShield remained at 0% ASR for A5 across both models.
