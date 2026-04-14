# Contributing to ZT-AgentShield

Thank you for helping improve this research artifact.

## Environment Setup

1. Create and activate a virtual environment.

```bash
python -m venv .venv
.\.venv\Scripts\activate
```

2. Install the project dependencies.

```bash
pip install -r requirements.txt
```

3. Configure API keys and local dataset access.

- `GROQ_API_KEY` for Groq-hosted models
- `OPENROUTER_API_KEY` for OpenRouter-hosted models
- `KAGGLE_USERNAME` and `KAGGLE_KEY` if you need to download the Enron dataset locally

4. Download the Enron dataset if it is not already present.

```bash
python scripts/download_enron.py
```

## Running Experiments

Run the main evaluations from the project root:

```bash
python attacks/run_all_attacks.py
python attacks/frontier_validation.py
```

These scripts write outputs to `results/`.

## Reporting Issues

When reporting a bug, include:

- the command you ran
- the model and environment variables used
- the Python version
- the exact error output
- whether the Enron dataset was present locally

Please open a GitHub issue with as much reproduction detail as possible so results can be verified quickly.
