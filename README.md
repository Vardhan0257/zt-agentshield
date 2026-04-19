## ⚠️ Artifact Scope (Important)

This repository contains multiple experimental components.

**The results reported in the paper are produced ONLY by:**

```bash
python attacks/run_all_attacks.py --n 20 --seeds 42,123,999
```

All other scripts (e.g., frontier validation, multi-agent experiments, OPA/Nemo integrations) are exploratory and NOT part of the core evaluation.

The paper focuses specifically on:

- trace-level enforcement
- lexical dependency detection
- semantic composition attacks
- invariance failure analysis

# ZT-AgentShield

ZT-AgentShield is a research artifact accompanying a paper on execution-boundary security for tool-using LLM agents. The repository contains the core agent implementations, attack benchmarks, and frontier-model validation scripts used to evaluate prompt-injection resilience, false-positive behavior, and multi-agent trust propagation.

## System Overview

ZT-AgentShield enforces execution-boundary security for LLM agents that interact with external tools. The system introduces attestation-aware tool execution and sequence-aware policy enforcement to prevent prompt injection attacks from triggering unsafe tool operations.

The artifact includes:

- baseline agents without protection
- a regex-based guardrail baseline
- the ZT-AgentShield enforcement layer
- attack benchmarks covering six prompt-injection classes
- multi-agent propagation experiments
- cross-model validation on frontier LLMs

## Environment Setup

Create a Python environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

If using OpenRouter or Groq APIs, set the following environment variables:

```bash
GROQ_API_KEY=...
OPENROUTER_API_KEY=...
```

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Project Structure

- `src/`: core agent implementations and defenses
- `attacks/`: attack and evaluation scripts
- `scripts/`: utility scripts for dataset download and debugging
- `data/`: local dataset inputs, including the Enron email subset
- `docs/`: threat model and paper-facing findings
- `results/`: generated experiment outputs
- `tests/`: small validation utilities

## Threat Model

The adversary can inject malicious text through direct user prompts, poisoned retrieved documents, and injected tool outputs. The system assumes the attacker cannot break attestation integrity or modify enclave state. The defended property is execution integrity: a tool call executes only when the attestation chain is valid and policy permits the action.

The formal threat model and security properties are documented in [docs/threat_model.md](docs/threat_model.md).

## Attack Taxonomy

The evaluation covers six attack families:

- A1: Direct prompt injection
- A2: Indirect injection via RAG
- A3: Role confusion jailbreak
- A4: Multi-hop tool result injection
- A5: Semantic composition attack
- A6: Mitigation evasion via keyword injection

A1-A4 test direct unsafe tool execution, A5 tests unsafe composition across individually allowed tools, and A6 demonstrates that static keyword-based mitigation is bypassable.

## Multi-Agent Experiments

ZT-AgentShield also evaluates trust propagation across a three-agent pipeline. The multi-agent experiments model a retriever, processor, and responder with attestation and sequence-aware enforcement. The benchmark includes cross-agent propagation and trust-chain poisoning attacks to test whether a compromised upstream agent can force unsafe downstream execution.

## Evaluated Models

The frontier evaluation script covers the following models:

- Llama-3.3-70B
- Qwen3-32B
- DeepSeek-Chat
- Qwen2.5-72B

The code automatically routes Groq-hosted models through Groq and OpenRouter-backed models through OpenRouter.

## Enron Dataset

The experiments use a local subset of the Enron email corpus stored at `data/enron/emails.csv`. The shared dataset loader reads a small slice of the corpus for fast, reproducible experiments and extracts real email addresses and message text for evaluation. The dataset is not required to be committed to the repository; download it locally before running the experiments.

To fetch the dataset, use:

```bash
python scripts/download_enron.py
```

## Reproducing the Experiments

Install dependencies, ensure the Enron dataset is available, and then run the two main experiment drivers from the project root.

```bash
python attacks/run_all_attacks.py
python attacks/frontier_validation.py
```

The scripts create the `results/` directory automatically and write CSV and JSON outputs there.

## Notes for Release

- Generated results are kept in `results/` and do not need to be committed.
- Environment variables are loaded from `.env` when present.
- Optional OpenRouter support is enabled automatically for DeepSeek-family models.

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
