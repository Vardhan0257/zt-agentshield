import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"


def _load_json(path):
    if not path.exists():
        raise RuntimeError(f"Missing required input: {path}")
    with open(path) as f:
        return json.load(f)


def generate_final_report():
    aggregate = _load_json(RESULTS_DIR / "aggregate_summary.json")
    failure_summary = _load_json(RESULTS_DIR / "failure_summary.json")
    spike = _load_json(RESULTS_DIR / "spike_analysis.json")
    run_id = aggregate.get("run_id") or failure_summary.get("run_id") or spike.get("run_id")

    final_report = {
        "run_id": run_id,
        "final_asr_table": {
            "baseline_mean_asr": aggregate.get("mean_baseline_asr"),
            "regex_mean_asr": aggregate.get("mean_regex_asr"),
            "zt_mean_asr": aggregate.get("mean_protected_asr"),
            "baseline_std": aggregate.get("std_baseline_asr"),
            "regex_std": aggregate.get("std_regex_asr"),
            "zt_std": aggregate.get("std_protected_asr"),
        },
        "per_round_asr": {
            "baseline": aggregate.get("per_round_avg_baseline_asr", []),
            "regex": aggregate.get("per_round_avg_regex_asr", []),
            "zt": aggregate.get("per_round_avg_protected_asr", []),
        },
        "smoothed_asr": aggregate.get("smoothed_asr_per_round", []),
        "unstable_rounds": aggregate.get("unstable_rounds", []),
        "failure_breakdown": failure_summary,
        "spike_analysis": spike,
        "baseline_comparison": {
            "baseline_vs_regex_gap": round(
                float(aggregate.get("mean_baseline_asr", 0.0)) - float(aggregate.get("mean_regex_asr", 0.0)),
                2,
            ),
            "baseline_vs_zt_gap": round(
                float(aggregate.get("mean_baseline_asr", 0.0)) - float(aggregate.get("mean_protected_asr", 0.0)),
                2,
            ),
            "regex_vs_zt_gap": round(
                float(aggregate.get("mean_regex_asr", 0.0)) - float(aggregate.get("mean_protected_asr", 0.0)),
                2,
            ),
        },
    }

    out_path = RESULTS_DIR / "final_report.json"
    with open(out_path, "w") as f:
        json.dump(final_report, f, indent=2)

    return final_report


def main():
    report = generate_final_report()
    table = report["final_asr_table"]
    print("Final ASR Table")
    print(f"Baseline mean/std: {table['baseline_mean_asr']} / {table['baseline_std']}")
    print(f"Regex mean/std: {table['regex_mean_asr']} / {table['regex_std']}")
    print(f"ZT mean/std: {table['zt_mean_asr']} / {table['zt_std']}")


if __name__ == "__main__":
    main()
