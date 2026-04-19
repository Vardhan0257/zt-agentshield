import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"


def _load_seed_summary(seed):
    path = RESULTS_DIR / f"seed_{seed}_summary.json"
    if not path.exists():
        raise RuntimeError(f"Missing seed summary file: {path}")
    with open(path) as f:
        data = json.load(f)
    if data.get("status") != "completed":
        raise RuntimeError(f"Seed {seed} failed: {data.get('error')}")
    if int(data.get("attempts", 0)) != 200:
        raise RuntimeError(f"Seed {seed} did not complete 200 prompts")
    return data


def _round_values(summary, key):
    rounds = summary.get("rounds_summary", [])
    if len(rounds) != 10:
        raise RuntimeError(f"Seed {summary.get('seed')} has invalid rounds_summary length")
    return [float(r.get(key, 0.0)) for r in rounds]


def _smoothed(values, window=3):
    out = []
    n = len(values)
    for i in range(n):
        left = max(0, i - 1)
        right = min(n - 1, i + 1)
        segment = values[left:right + 1]
        out.append(round(sum(segment) / len(segment), 2))
    return out


def aggregate_seed_results(seeds, unstable_threshold=20.0):
    summaries = [_load_seed_summary(seed) for seed in seeds]
    run_ids = {s.get("run_id") for s in summaries if s.get("run_id")}
    if len(run_ids) > 1:
        raise RuntimeError("Stale artifact detected")
    run_id = next(iter(run_ids)) if run_ids else None

    baseline = [float(s.get("baseline_asr", 0.0)) for s in summaries]
    regex = [float(s.get("regex_asr", 0.0)) for s in summaries]
    protected = [float(s.get("protected_asr", 0.0)) for s in summaries]

    per_round_baseline = []
    per_round_regex = []
    per_round_protected = []
    per_round_std = []

    for i in range(10):
        b_vals = [_round_values(s, "baseline_asr")[i] for s in summaries]
        r_vals = [_round_values(s, "regex_asr")[i] for s in summaries]
        p_vals = [_round_values(s, "protected_asr")[i] for s in summaries]

        per_round_baseline.append(round(statistics.mean(b_vals), 2))
        per_round_regex.append(round(statistics.mean(r_vals), 2))
        per_round_protected.append(round(statistics.mean(p_vals), 2))
        per_round_std.append(round(statistics.pstdev(p_vals), 2))

    unstable_rounds = [
        i + 1 for i, std_val in enumerate(per_round_std) if std_val > unstable_threshold
    ]

    aggregate = {
        "run_id": run_id,
        "seeds": seeds,
        "mean_baseline_asr": round(statistics.mean(baseline), 2),
        "mean_regex_asr": round(statistics.mean(regex), 2),
        "mean_protected_asr": round(statistics.mean(protected), 2),
        "std_baseline_asr": round(statistics.pstdev(baseline), 2),
        "std_regex_asr": round(statistics.pstdev(regex), 2),
        "std_protected_asr": round(statistics.pstdev(protected), 2),
        "per_round_avg_baseline_asr": per_round_baseline,
        "per_round_avg_regex_asr": per_round_regex,
        "per_round_avg_protected_asr": per_round_protected,
        "smoothed_asr_per_round": _smoothed(per_round_protected, window=3),
        "per_round_std_protected_asr": per_round_std,
        "unstable_threshold": unstable_threshold,
        "unstable_rounds": unstable_rounds,
    }

    out_path = RESULTS_DIR / "aggregate_summary.json"
    with open(out_path, "w") as f:
        json.dump(aggregate, f, indent=2)

    if aggregate["std_protected_asr"] > 10:
        print("[WARN] High variance across seeds — results may be unstable")

    return aggregate


def analyze_spikes(seeds):
    summaries = [_load_seed_summary(seed) for seed in seeds]
    run_ids = {s.get("run_id") for s in summaries if s.get("run_id")}
    if len(run_ids) > 1:
        raise RuntimeError("Stale artifact detected")
    run_id = next(iter(run_ids)) if run_ids else None

    merged_results = []
    for s in summaries:
        for row in s.get("results", []):
            merged_results.append({
                "seed": s.get("seed"),
                **row,
            })

    # Use protected success as the key spike signal.
    round_success = {}
    for round_id in range(1, 11):
        rows = [r for r in merged_results if int(r.get("round", 0)) == round_id]
        if not rows:
            round_success[round_id] = 0.0
            continue
        score = 100.0 * sum(1 for r in rows if r.get("protected_success")) / len(rows)
        round_success[round_id] = round(score, 2)

    highest_round = max(round_success.items(), key=lambda x: x[1])[0]
    lowest_round = min(round_success.items(), key=lambda x: x[1])[0]

    def top_prompts_for_round(round_id):
        rows = [r for r in merged_results if int(r.get("round", 0)) == round_id]
        rows = [r for r in rows if r.get("protected_success")]
        rows = sorted(rows, key=lambda x: len(str(x.get("protected_trace", []))), reverse=True)
        return [
            {
                "seed": r.get("seed"),
                "prompt": r.get("prompt"),
                "protected_trace": r.get("protected_trace", []),
            }
            for r in rows[:5]
        ]

    spike = {
        "run_id": run_id,
        "highest_asr_round": {
            "round": highest_round,
            "protected_asr": round_success[highest_round],
            "top_prompts": top_prompts_for_round(highest_round),
        },
        "lowest_asr_round": {
            "round": lowest_round,
            "protected_asr": round_success[lowest_round],
            "top_prompts": top_prompts_for_round(lowest_round),
        },
    }

    out_path = RESULTS_DIR / "spike_analysis.json"
    with open(out_path, "w") as f:
        json.dump(spike, f, indent=2)

    return spike


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", required=True, help="Comma-separated list, e.g. 42,123,999")
    parser.add_argument("--unstable-threshold", type=float, default=20.0)
    args = parser.parse_args()

    seeds = [int(x.strip()) for x in args.seeds.split(",") if x.strip()]
    aggregate = aggregate_seed_results(seeds, unstable_threshold=args.unstable_threshold)
    analyze_spikes(seeds)

    print(f"Mean ASR -> {aggregate['mean_protected_asr']}%")
    print(f"Std -> {aggregate['std_protected_asr']}%")
    for idx, value in enumerate(aggregate['per_round_avg_protected_asr'], start=1):
        print(f"Round {idx} -> {value}%")


if __name__ == "__main__":
    main()
