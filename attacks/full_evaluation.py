import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_step(label, cmd):
    print("\n" + "=" * 72)
    print(f"{label}")
    print("=" * 72)
    print(" ".join(cmd))
    proc = subprocess.run(cmd, cwd=str(ROOT))
    if proc.returncode != 0:
        raise RuntimeError(f"Step failed ({label}) with exit code {proc.returncode}")


def run_full_evaluation(skip_adaptive=False):
    py = sys.executable

    run_step("Main attacks", [py, "attacks/run_all_attacks.py"])
    run_step("Ablation", [py, "attacks/run_all_attacks.py", "--ablation"])
    run_step("Multi-agent", [py, "attacks/run_all_attacks.py", "--multi-agent"])
    run_step("Phase3 fair baselines", [py, "attacks/phase3_baselines.py"])
    run_step("Frontier validation", [py, "attacks/frontier_validation.py"])

    if not skip_adaptive:
        run_step("Adaptive adversary", [py, "attacks/adaptive_adversary.py"])

    print("\nAll evaluation phases completed successfully.")


if __name__ == "__main__":
    skip = "--skip-adaptive" in sys.argv
    run_full_evaluation(skip_adaptive=skip)
