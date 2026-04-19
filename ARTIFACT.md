# Artifact Reproduction Guide

## Main Result Reproduction

Run:

```bash
python attacks/run_all_attacks.py --n 20 --seeds 42,123,999
```

## Output Files

- results/final_experiment.json
- results/baseline_comparison_summary.json
- results/failure_summary.json

## Dataset

- Semantic composition dataset (SC1-SC50)
- Multihop dataset

## Determinism

- Fixed dataset
- Deterministic planner
- Seed-controlled execution

## Notes

- Other scripts in the repository are NOT required to reproduce the main results.
- These include frontier validation, multi-agent experiments, and external integrations.
